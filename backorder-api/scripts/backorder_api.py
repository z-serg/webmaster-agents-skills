#!/usr/bin/env python3
"""Build public Backorder.ru URLs or save one validated response (Python 3.10+)."""

import argparse
import csv
import io
import json
import re
import sys
import time
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

BASE = "https://backorder.ru"
MULTI = {"include", "exclude", "zones", "registrars"}
METRICS = {"x_value", "yandex_tic", "donors", "visitors", "old"}
DATES = {"freedate_start", "freedate_end", "create_date_ge", "create_date_le"}
AGE_SORT = {"age", "age_first_reg", "age_prev_reg"}
ENUMS = {
    "filter_params": {"all_domains", "deleted_today", "deleted_next", "expired",
                      "freed_today", "is_free", "judicial", "stop_list"},
    "old_type": {"current_creation", "first_creation", "previous_creation"},
    "real_free_date": {"on", "off"},
    "sort_order": {"asc", "desc"},
    "content_only": {"on", "off"},
    "exact_first": {"on", "off"},
    "order_by": {"domain", "hotness", "price_next", "x_value", "tic", "donors",
                 "traffic", "registrar", "age", "age_first_reg", "age_prev_reg", "date"},
    "include": {"interesting", "org", "person", "pendingdelete", "rkn", "my_orders"},
    "exclude": {"dash", "digits", "letters", "letterdigit", "traffic", "expired",
                "free", "judicial", "blocked", "interesting", "pendingdelete", "rkn"},
}
ALLOWED = set(ENUMS) | MULTI | METRICS | DATES | {
    "contains", "org", "length_ge", "length_le", "limit", "offset"
}


def tokens(value):
    values = value if isinstance(value, list) else [value]
    if any(not isinstance(v, str) for v in values):
        raise ValueError("List parameters require strings or lists of strings")
    return list(dict.fromkeys(t.strip() for v in values
                              for t in re.split(r"[,|]", str(v)) if t.strip()))


def load_params(raw_json=None, source_url=None):
    if raw_json is not None:
        params = json.loads(raw_json)
        if not isinstance(params, dict):
            raise ValueError("--params must be a JSON object")
        return params
    if source_url is None:
        return {}
    parsed = urlsplit(source_url)
    if (parsed.scheme != "https" or parsed.netloc != "backorder.ru"
            or parsed.path not in {"", "/", "/json/", "/csv/", "/billmgr"}):
        raise ValueError("Use an HTTPS backorder.ru page, export or billmgr URL")
    is_hash = bool(parsed.fragment)
    if is_hash and parsed.query:
        raise ValueError("URL has both query and hash; choose one source explicitly")
    if is_hash and parsed.path not in {"", "/"}:
        raise ValueError("A frontend hash is supported only on the home page")
    parsed_values = parse_qs(parsed.fragment if is_hash else parsed.query,
                             keep_blank_values=True)
    params = {}
    for key, values in parsed_values.items():
        if key in MULTI or key == "domain":
            params[key] = tokens(values)
        elif len(values) != 1:
            raise ValueError(f"Repeated scalar parameter: {key}")
        else:
            params[key] = values[0]
    if is_hash and "|" in str(params.get("contains", "")):
        raise ValueError("The UI may treat contains with | as exact mget. "
                         "Use --target mget --params with domain names, or explicit "
                         "--params for intentional API patterns")
    if parsed.path in {"", "/"}:
        params = {"limit": 50, "offset": 0, "sort_order": "desc",
                  "order_by": "hotness", "filter_params": "expired", **params}
    if is_hash and params.get("order_by") in AGE_SORT:
        direction = params.get("sort_order", "desc")
        if direction not in {"asc", "desc"}:
            raise ValueError("Invalid hash sort_order")
        params["sort_order"] = "desc" if direction == "asc" else "asc"
    # UI-only state. Do not carry it into a data request.
    params.pop("ext", None)
    return params


def normalize(params, target):
    params = {k: v for k, v in params.items() if v is not None and v != "" and v != []}
    expected_func = "backorder_list.mget" if target == "mget" else "backorder_list"
    for key, expected in {"func": expected_func, "out": "backorder", "filter": "off"}.items():
        if key in params and params.pop(key) != expected:
            raise ValueError(f"Unexpected {key}; expected {expected}")
    if target == "mget":
        if set(params) != {"domain"}:
            raise ValueError("mget accepts only a nonempty domain list; apply filters locally")
        domains = tokens(params["domain"])
        if not domains or any(not re.fullmatch(r"[^\s/?#*^!$,:|]+\.[^\s/?#*^!$,:|]+", d)
                              for d in domains):
            raise ValueError("mget needs exact domain names, without URL or wildcard syntax")
        return {"func": expected_func, "out": "backorder", "domain": ",".join(domains)}
    unknown = set(params) - ALLOWED
    if unknown:
        raise ValueError("Unknown/legacy/secret parameters: " + ", ".join(sorted(unknown)))
    if params.get("filter_params") == "cart":
        raise ValueError("cart is browser-local; provide concrete domains to mget")
    for key in MULTI & params.keys():
        values = tokens(params[key])
        if key == "exclude" and set(values) & {"in_cart", "ordered"}:
            raise ValueError("in_cart/ordered need explicit client-side handling; see filters.md")
        params[key] = ",".join(values)
    for key, value in params.items():
        if isinstance(value, (dict, list, bool)):
            raise ValueError(f"Invalid scalar value for {key}")
        if key in ENUMS:
            values = value.split(",") if key in MULTI else [str(value)]
            if any(v not in ENUMS[key] for v in values):
                raise ValueError(f"Unsupported {key}: {value}")
        if key in DATES:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(value)):
                raise ValueError(f"{key} requires YYYY-MM-DD")
            date.fromisoformat(value)
        if key in METRICS | {"limit", "offset", "length_ge", "length_le"}:
            if not re.fullmatch(r"\d+", str(value)):
                raise ValueError(f"{key} requires a nonnegative integer")
            number = int(value)
            lo, hi = (2, 63) if key.startswith("length_") else (0, 4294967295)
            if key == "limit":
                hi = 30000
            if not lo <= number <= hi:
                raise ValueError(f"{key} outside {lo}..{hi}")
    for lower, upper in [("length_ge", "length_le"), ("freedate_start", "freedate_end"),
                         ("create_date_ge", "create_date_le")]:
        if lower in params and upper in params:
            left, right = params[lower], params[upper]
            if lower == "length_ge":
                left, right = int(left), int(right)
            if left > right:
                raise ValueError(f"{lower} must not exceed {upper}")
    if "my_orders" in tokens(params.get("include", "")):
        raise ValueError("my_orders requires authorization; this helper is public-only")
    params.setdefault("filter_params", "expired")
    if target == "api":
        return {"func": "backorder_list", "out": "backorder", "filter": "off", **params}
    for key in ("limit", "offset", "content_only"):
        params.pop(key, None)  # Export ignores pagination and returns a flat schema.
    return params


def build_url(target, params):
    normalized = normalize(dict(params), target)
    path = "/billmgr" if target in {"api", "mget"} else f"/{target}/"
    return BASE + path + "?" + urlencode(normalized)


def parse_response(body, target, content_type=""):
    text = body.decode("utf-8-sig")
    if "text/html" in content_type.lower() or text.lstrip().startswith("<"):
        raise ValueError("HTML/CAPTCHA instead of data; stop and open the site in Chrome")
    if target == "csv":
        reader = csv.DictReader(io.StringIO(text), delimiter=";")
        if not reader.fieldnames or "domainname" not in reader.fieldnames:
            raise ValueError("Unexpected CSV header (expected semicolon-separated domainname)")
        return sum(1 for _ in reader)
    data = json.loads(text)
    if isinstance(data, dict) and "error" in data:
        error = data["error"]
        message = error.get("type", "API error") if isinstance(error, dict) else str(error)
        raise ValueError("API error: " + message)
    if target == "json":
        if not isinstance(data, list):
            raise ValueError("Export JSON must be an array")
        rows, field = data, "domainname"
    else:
        if not isinstance(data, dict) or not isinstance(data.get("records"), list):
            raise ValueError("API JSON must contain a records array")
        rows, field = data["records"], "domain"
    if any(not isinstance(row, dict) or field not in row for row in rows):
        raise ValueError(f"Unexpected record schema: missing {field}")
    return len(rows)


def retry_delay(header, attempt):
    minimum = 1.2 * (2 ** attempt)
    if not header:
        return minimum
    try:
        value = float(header)
    except ValueError:
        try:
            dt = parsedate_to_datetime(header)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            value = (dt - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return minimum
    delay = max(minimum, value)
    if delay > 60:
        raise ValueError("Retry-After exceeds 60 seconds; retry later")
    return delay


def download(url, target, timeout=30):
    request = Request(url, headers={"Accept": "text/csv" if target == "csv"
                                   else "application/json", "User-Agent": "BackorderSkill/1.0"})
    for attempt in range(3):
        try:
            with urlopen(request, timeout=timeout) as response:
                if urlsplit(response.url).netloc != "backorder.ru":
                    raise ValueError("Unexpected redirect; stop and inspect access in Chrome")
                body = response.read()
                count = parse_response(body, target, response.headers.get("Content-Type", ""))
                return body, count
        except HTTPError as error:
            body = error.read()
            try:
                error_obj = json.loads(body).get("error", {})
            except (ValueError, AttributeError, UnicodeDecodeError):
                error_obj = {}
            if isinstance(error_obj, dict) and error_obj.get("type") == "access_blocked":
                raise ValueError("access_blocked: stop requests; inspect access in Chrome") from None
            if body.lstrip().startswith(b"<"):
                raise ValueError(f"HTTP {error.code} with HTML/CAPTCHA; stop requests") from None
            if error.code != 429 or attempt == 2:
                raise ValueError(f"HTTP {error.code}; response not saved") from None
            time.sleep(retry_delay(error.headers.get("Retry-After"), attempt))
    raise RuntimeError("Unreachable")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["url", "fetch"])
    parser.add_argument("--target", choices=["api", "json", "csv", "mget"], default="api")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--params", help="JSON object of server-side query parameters")
    source.add_argument("--from-url", help="Current frontend hash or API/export URL")
    parser.add_argument("--output", type=Path, help="Save successful response here (required for fetch)")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    try:
        if args.timeout <= 0:
            raise ValueError("--timeout must be positive")
        params = load_params(args.params, args.from_url)
        url = build_url(args.target, params)
        if args.action == "url":
            print(url)
            return 0
        if args.output is None:
            raise ValueError("fetch requires --output")
        body, count = download(url, args.target, args.timeout)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(body)
        print(json.dumps({"path": str(args.output.resolve()), "rows": count,
                          "bytes": len(body), "complete_selection": "not_assessed"},
                         ensure_ascii=False))
        return 0
    except (ValueError, TypeError, OSError, URLError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
