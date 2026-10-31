#!/usr/bin/env python3
"""WHOIS/RDAP and Wayback checks with evidence, conservative states and resume.

Python 3 standard library only. Search-engine checks are deliberately left
as a browser queue; this script never labels a domain's history as clean.
"""

import argparse
import csv
import html
import io
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen


MAX_BYTES = 2_000_000
CDX_LIMIT = 20
DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                       r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
BLOCK_RE = re.compile(r"(?:complete|solve|enter|requires?) (?:the |a )?captcha|"
                      r"captcha (?:required|challenge)|access denied|rate limit exceeded|query limit exceeded|"
                      r"too many (?:requests|queries)|quota exceeded|"
                      r"temporarily unavailable|service unavailable|request blocked", re.I)
FINAL_WHOIS = {"taken", "available", "no_record"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize(value):
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or not value.isascii() or not DOMAIN_RE.fullmatch(value):
        raise ValueError(f"Invalid ASCII domain (no URL/path/port): {value!r}")
    return value


def read_domains(path):
    values = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        values.extend(normalize(token) for token in line.split("#", 1)[0].split())
    return list(dict.fromkeys(values))


def atomic_text(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(value, encoding="utf-8")
    temp.replace(path)


def write_json(path, value):
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def write_csv(path, rows, fields):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    atomic_text(path, stream.getvalue())


def parse_whois(text, domain):
    if BLOCK_RE.search(text):
        return {"status": "unknown", "reason": "WHOIS blocked or rate limited"}
    names = re.findall(r"^\s*(?:domain|domain name)\s*:\s*(\S+)", text, re.I | re.M)
    matching = any(name.lower().rstrip(".") == domain for name in names)
    # Require an explicit no-record line, not a footer mentioning WHOIS policy.
    empty = bool(re.search(
        r"^\s*(?:No entries found for the selected source\(s\)\.?|"
        r"NOT FOUND\.?|Domain not found\.?|No Data Found\.?)\s*$", text, re.I | re.M))
    for name in re.findall(r'^\s*No match for\s+[\"\']?([^\s\"\']+)', text, re.I | re.M):
        if name.rstrip(".").lower() == domain:
            empty = True
    if matching and empty:
        return {"status": "unknown", "reason": "Conflicting record and no-record statements"}
    if matching:
        created = re.search(r"^\s*(?:created|creation date|registered on)\s*:\s*(\S+)",
                            text, re.I | re.M)
        return {"status": "taken", "created": created.group(1) if created else "",
                "reason": "WHOIS record matches the queried domain"}
    if empty and not names:
        return {"status": "available", "reason": "WHOIS explicitly reports no record"}
    return {"status": "unknown", "reason": "Unrecognized WHOIS or domain mismatch"}


def whois_html_text(text):
    # Parse only result blocks; menus, ads and scripts may mention other domains.
    blocks = re.findall(r"<pre\b[^>]*>(.*?)</pre>", text, re.I | re.S)
    return "\n".join(html.unescape(re.sub(r"<[^>]+>", "", block)) for block in blocks)


def parse_rdap(code, text, domain):
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {"status": "unknown", "reason": "RDAP did not return JSON"}
    if not isinstance(data, dict):
        return {"status": "unknown", "reason": "Unexpected RDAP structure"}
    if code == 404 and data.get("errorCode") == 404:
        return {"status": "no_record", "reason": "Authoritative RDAP returned no object; registration availability unverified"}
    if (code == 200 and data.get("objectClassName") == "domain"
            and str(data.get("ldhName", "")).lower().rstrip(".") == domain):
        events = data.get("events", [])
        if not isinstance(events, list):
            events = []
        created = next((event.get("eventDate", "") for event in events
                        if isinstance(event, dict) and event.get("eventAction") == "registration"), "")
        return {"status": "taken", "created": created, "reason": "RDAP object matches the queried domain"}
    return {"status": "unknown", "reason": f"RDAP HTTP {code}: no matching domain object"}


def parse_cdx(text, domain, limit=CDX_LIMIT):
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {"status": "unknown", "reason": "Archive did not return JSON"}
    if data == []:
        return {"status": "no_captures", "sample_count": 0, "samples": []}
    required = {"timestamp", "original", "statuscode", "mimetype"}
    if (not isinstance(data, list) or not data or not isinstance(data[0], list)
            or not all(isinstance(field, str) for field in data[0])
            or len(data[0]) != len(set(data[0])) or not required.issubset(data[0])):
        return {"status": "unknown", "reason": "Unexpected CDX header"}
    samples = []
    for row in data[1:]:
        if (not isinstance(row, list) or len(row) != len(data[0])
                or not all(isinstance(value, str) for value in row)):
            return {"status": "unknown", "reason": "Malformed CDX row"}
        entry = dict(zip(data[0], row))
        try:
            original = urlsplit(entry["original"])
            host = (original.hostname or "").lower().rstrip(".")
        except ValueError:
            return {"status": "unknown", "reason": "Invalid CDX original URL"}
        if (not re.fullmatch(r"\d{14}", entry["timestamp"])
                or original.scheme not in {"http", "https"}
                or not (host == domain or host.endswith("." + domain))):
            return {"status": "unknown", "reason": "CDX timestamp or domain mismatch"}
        entry["snapshot_url"] = ("https://web.archive.org/web/" + entry["timestamp"]
                                 + "/" + entry["original"])
        samples.append(entry)
    stamps = [row["timestamp"] for row in samples]
    return {"status": "captures" if samples else "no_captures",
            "sample_count": len(samples), "sample_first": min(stamps, default=""),
            "sample_last": max(stamps, default=""), "limit_reached": len(samples) >= limit,
            "samples": samples}


class Research:
    def __init__(self, out, timeout=20, delay=1.2):
        self.out, self.timeout, self.delay = out, timeout, delay
        self.last_request = 0
        self.disabled = {}
        self.servers = {"ru": "whois.tcinet.ru", "su": "whois.tcinet.ru"}
        self.bootstrap = None

    def pause(self):
        remaining = self.delay - (time.monotonic() - self.last_request)
        if remaining > 0:
            time.sleep(remaining)
        self.last_request = time.monotonic()

    def request(self, record, source, query=None):
        key = source if query is not None else urlsplit(source).netloc
        attempt = {"source": source, "query": query or "", "checked_at": now()}
        record["attempts"].append(attempt)
        if key in self.disabled:
            attempt["error"] = "Skipped for this run: " + self.disabled[key]
            return attempt, ""
        self.pause()
        try:
            if query is not None:
                deadline = time.monotonic() + self.timeout
                with socket.create_connection((source, 43), timeout=self.timeout) as conn:
                    conn.sendall((query + "\r\n").encode("ascii"))
                    chunks, size = [], 0
                    while True:
                        conn.settimeout(max(0.01, deadline - time.monotonic()))
                        part = conn.recv(min(65536, MAX_BYTES + 1 - size))
                        if not part:
                            break
                        chunks.append(part)
                        size += len(part)
                        if size > MAX_BYTES:
                            raise ValueError("Response size limit exceeded")
                        if time.monotonic() >= deadline:
                            raise TimeoutError("WHOIS response deadline exceeded")
                code, body = 200, b"".join(chunks)
            else:
                request = Request(source, headers={"User-Agent": "DomainNameResearch/1.0",
                                                   "Accept-Encoding": "identity"})
                try:
                    response = urlopen(request, timeout=self.timeout)
                except HTTPError as error:
                    response = error
                with response:
                    code, body = response.code, response.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise ValueError("Response size limit exceeded")
            text = body.decode("utf-8", errors="replace")
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            raw = self.out / "raw" / record["stage"] / record["domain"] / f"{stamp}.txt"
            atomic_text(raw, text)
            attempt.update({"http_status": code, "evidence": str(raw.resolve())})
            if code in {403, 429} or code >= 500:
                self.disabled[key] = f"HTTP {code}; see {raw}"
            return attempt, text
        except (OSError, ValueError) as error:
            attempt["error"] = f"{type(error).__name__}: {error}"
            self.disabled[key] = attempt["error"]
            return attempt, ""

    @staticmethod
    def failure(attempt):
        if "error" in attempt:
            return {"status": "error", "reason": attempt["error"]}
        code = attempt.get("http_status")
        return {"status": "unknown" if code in {403, 429} else "error",
                "reason": f"Service HTTP {code}"}

    def registry(self, record, server=None):
        domain, tld = record["domain"], record["domain"].rsplit(".", 1)[-1]
        if not server and tld not in self.servers:
            attempt, text = self.request(record, "whois.iana.org", query=tld)
            match = re.search(r"^whois:\s*([a-z0-9.-]+)\s*$", text, re.I | re.M)
            if "error" in attempt:
                return self.failure(attempt)
            self.servers[tld] = match.group(1) if match else None
        server = server or self.servers.get(tld)
        if not server:
            return {"status": "unknown", "reason": "No WHOIS server found in IANA; try RDAP"}
        attempt, text = self.request(record, server, query=domain)
        if "error" in attempt:
            return self.failure(attempt)
        result = parse_whois(text, domain)
        if result.get("reason") == "WHOIS blocked or rate limited":
            self.disabled[server] = result["reason"]
        return dict(result, source=server)

    def whois_vu(self, record):
        if record["domain"].rsplit(".", 1)[-1] not in {"ru", "su"}:
            return {"status": "unknown", "reason": "WHOIS.vu fallback is scoped to .ru/.su"}
        url = "https://whois.vu/?" + urlencode({"q": record["domain"]})
        attempt, text = self.request(record, url)
        if "error" in attempt or attempt["http_status"] != 200:
            return self.failure(attempt)
        result_text = whois_html_text(text)
        result = parse_whois(result_text, record["domain"])
        if not result_text or result.get("reason") == "WHOIS blocked or rate limited":
            self.disabled[urlsplit(url).netloc] = "No WHOIS result block, or service block"
        return dict(result, source=url)

    def rdap(self, record):
        if self.bootstrap is None:
            url = "https://data.iana.org/rdap/dns.json"
            attempt, text = self.request(record, url)
            if "error" in attempt or attempt["http_status"] != 200:
                return self.failure(attempt)
            try:
                self.bootstrap = json.loads(text)["services"]
                if not isinstance(self.bootstrap, list):
                    raise ValueError("Invalid services list")
            except (ValueError, KeyError, TypeError):
                self.disabled[urlsplit(url).netloc] = "Invalid IANA RDAP bootstrap"
                return {"status": "unknown", "reason": "Invalid IANA RDAP bootstrap"}
        tld = record["domain"].rsplit(".", 1)[-1]
        bases = []
        for service in self.bootstrap:
            if isinstance(service, list) and len(service) == 2:
                zones, urls = service
                if isinstance(zones, list) and isinstance(urls, list) and tld in zones:
                    bases.extend(url for url in urls if isinstance(url, str) and url.startswith("https://"))
        if not bases:
            return {"status": "unknown", "reason": "No HTTPS RDAP service listed by IANA"}
        url = bases[0].rstrip("/") + "/domain/" + quote(record["domain"], safe="")
        attempt, text = self.request(record, url)
        if "error" in attempt or attempt["http_status"] not in {200, 404}:
            return self.failure(attempt)
        return dict(parse_rdap(attempt["http_status"], text, record["domain"]), source=url)

    def whois(self, domain, backend="auto", server=None):
        record = {"domain": domain, "stage": "whois", "checked_at": now(), "attempts": []}
        backends = ["registry", "whois-vu", "rdap"] if backend == "auto" else [backend]
        outcomes = []
        for name in backends:
            result = (self.registry(record, server) if name == "registry" else
                      self.whois_vu(record) if name == "whois-vu" else self.rdap(record))
            outcomes.append(dict(result, backend=name))
            if result["status"] in FINAL_WHOIS:
                record.update(result, backend=name, outcomes=outcomes)
                return record
        # Do not let an unsupported fallback hide the original network failure.
        final = next((row for row in outcomes if row["status"] == "error"), outcomes[-1])
        record.update(final, outcomes=outcomes)
        return record

    def archive(self, domain):
        url = "http://web.archive.org/cdx/search/cdx?" + urlencode({
            # CDX's documented wildcard form implies matchType=domain.
            "url": "*." + domain + "/", "output": "json",
            "fl": "timestamp,original,statuscode,mimetype", "limit": CDX_LIMIT,
            "collapse": "timestamp:6", "gzip": "false"})
        record = {"domain": domain, "stage": "archive", "checked_at": now(),
                  "source": url, "attempts": []}
        attempt, text = self.request(record, url)
        result = (self.failure(attempt) if "error" in attempt or attempt["http_status"] != 200
                  else parse_cdx(text, domain))
        record.update(result)
        return record


def update_search_queue(path, domains):
    fields = ["domain", "engine", "query", "url", "status", "checked_at", "evidence", "notes"]
    rows = []
    if path.exists():
        with path.open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != fields:
                raise ValueError(f"Unexpected columns in {path}; preserve and inspect it manually")
            rows = list(reader)
    existing = {(row["domain"], row["engine"]) for row in rows}
    for domain in domains:
        query = '"' + domain + '"'
        for engine, base, param in [("google", "https://www.google.com/search?", "q"),
                                     ("yandex", "https://yandex.ru/search/?", "text")]:
            if (domain, engine) not in existing:
                rows.append({"domain": domain, "engine": engine, "query": query,
                             "url": base + urlencode({param: query}), "status": "pending"})
                existing.add((domain, engine))
    write_csv(path, rows, fields)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["whois", "archive"])
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--delay", type=float, default=1.2)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--backend", choices=["auto", "registry", "whois-vu", "rdap"], default="auto")
    parser.add_argument("--whois-server")
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.delay < 0:
        parser.error("--timeout must be positive and --delay nonnegative")
    if args.whois_server and not re.fullmatch(r"[a-zA-Z0-9.-]+", args.whois_server):
        parser.error("--whois-server must be a hostname")
    try:
        domains = read_domains(args.input)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if not domains:
        print("No domains to check; existing outputs were preserved.")
        return 0
    research, rows = Research(args.out, args.timeout, args.delay), []
    for domain in domains:
        cache = args.out / args.stage / (domain + ".json")
        if cache.exists() and not args.refresh:
            record = json.loads(cache.read_text(encoding="utf-8"))
            if record.get("domain") != domain or record.get("stage") != args.stage:
                raise ValueError(f"Invalid cache: {cache}")
            cached = True
        else:
            record = (research.whois(domain, args.backend, args.whois_server)
                      if args.stage == "whois" else research.archive(domain))
            write_json(cache, record)
            cached = False
        rows.append(record)
        print(f"{domain:<35} {record['status']:<12} {record['checked_at']}"
              + (" (cached)" if cached else ""), flush=True)
    write_json(args.out / (args.stage + ".json"), rows)
    fields = ["domain", "status", "checked_at", "source", "backend", "created", "reason"]
    if args.stage == "archive":
        fields += ["sample_count", "sample_first", "sample_last", "limit_reached"]
    write_csv(args.out / (args.stage + ".csv"), rows, fields)
    if args.stage == "whois":
        available = [row["domain"] for row in rows if row["status"] in {"available", "no_record"}]
        atomic_text(args.out / "available.txt", "".join(domain + "\n" for domain in available))
        update_search_queue(args.out / "search_queue.csv", available)
    counts = {state: sum(row["status"] == state for row in rows)
              for state in sorted({row["status"] for row in rows})}
    print(json.dumps(counts, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted; individual results preserved. Rerun to resume.", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
