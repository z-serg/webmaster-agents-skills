#!/usr/bin/env python3
"""Локальный технический SEO-аудит сайта без сторонних сервисов.

Только стандартная библиотека Python 3.8+. Заменяет облачные краулеры
(Site Analyzer, Screaming Frog и т. п.) для проверок, которые агент может
выполнить сам: robots.txt, sitemap.xml, зеркала, SSL, битые ссылки,
редиректы, мета-теги, дубли, текст, микроразметка, счётчики, favicon.

Команды:
  audit  URL   полный аудит: проверки сайта + обход + сводка (site+crawl+report)
  site   URL   только проверки уровня сайта (robots, sitemap, зеркала, SSL, 404)
  crawl  URL   обход сайта, сбор данных по страницам -> pages.json
  report FIFE  сводка по данным краула -> summary.md + issues.csv
  urls --input FILE  точечная проверка списка URL (статусы, редиректы, мета)

Пример:
  python3 site_audit.py audit https://example.ru --out work/audit --max-pages 200
"""
import argparse
import csv
import datetime
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
import xml.etree.ElementTree as ET
from collections import Counter, deque
from html.parser import HTMLParser

UA = "Mozilla/5.0 (compatible; seo-specialist-audit/1.0; +local script)"
TIMEOUT = 20
SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
            ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".pdf",
            ".zip", ".rar", ".7z", ".gz", ".tar", ".mp3", ".mp4", ".avi",
            ".mov", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")
STOPWORDS = set("""
и в во не что он на я с со как а то все она так его но да ты к у же
вы за бы по только ее мне было вот от меня еще нет о из ему теперь
когда даже ну вдруг ли если уже или ни быть был него до вас нибудь
опять уж вам сказал ведь там потом себя ничего ей может они тут где
есть надо ней для мы тебя их чем была сам чтоб без будто человек чего
раз тоже себе под жизнь будет ж тогда кто этот говорил того потому
этого какой совсем ним здесь этом один почти мой тем чтобы нее seems
the and for are but not you all any can had her was one our out day
get has him his how man new now old see two way who boy did its let
put say she too use avec это эта эти этот рынок также более
""".split())


def die(msg):
    print("Ошибка: %s" % msg, file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- HTTP layer

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CIDict(dict):
    """Словарь заголовков без учёта регистра ключей."""

    def __init__(self, items=()):
        super().__init__()
        for k, v in items:
            self[(k or "").lower()] = v

    def get(self, key, default=None):
        return super().get((key or "").lower(), default)

    def __contains__(self, key):
        return super().__contains__((key or "").lower())


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch(url, method="GET", timeout=TIMEOUT):
    """Запрос без авто-перехода; возвращает цепочку редиректов и тело."""
    chain = []
    current = url
    body = b""
    headers = {}
    status = 0
    err = None
    t0 = time.monotonic()
    for _ in range(10):
        req = urllib.request.Request(current, method=method, headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "ru,en;q=0.9",
            "Accept-Encoding": "identity",
        })
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                status = resp.status
                headers = CIDict(resp.headers.items())
                if method == "GET":
                    body = resp.read(3 * 1024 * 1024)
            chain.append((current, status))
            err = None
            break
        except urllib.error.HTTPError as e:
            status = e.code
            headers = CIDict(e.headers.items()) if e.headers else CIDict()
            chain.append((current, status))
            loc = headers.get("Location")
            if status in (301, 302, 303, 307, 308) and loc:
                current = urllib.parse.urljoin(current, loc)
                continue
            if method == "GET":
                try:
                    body = e.read(1024 * 1024)
                except Exception:
                    body = b""
            err = "HTTP %d" % status
            break
        except Exception as e:  # таймауты, DNS, обрывы
            chain.append((current, 0))
            err = "%s: %s" % (type(e).__name__, e)
            break
    return {
        "start": url,
        "final": chain[-1][0] if chain else url,
        "chain": chain,
        "status": status,
        "headers": headers,
        "body": body,
        "elapsed": round(time.monotonic() - t0, 3),
        "error": err,
    }


def decode_body(resp):
    ctype = resp["headers"].get("Content-Type", "")
    m = re.search(r"charset=([\w-]+)", ctype)
    enc = m.group(1) if m else "utf-8"
    try:
        return resp["body"].decode(enc, errors="replace")
    except LookupError:
        return resp["body"].decode("utf-8", errors="replace")


# ----------------------------------------------------------------- HTML parse

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.metas = {}
        self.canonical = None
        self.icon_link = False
        self.h1 = []
        self.h2 = 0
        self._h1_buf = []
        self._in_h1 = False
        self.links = []
        self.img_total = 0
        self.img_no_alt = 0
        self.ldjson = []
        self._ldjson_buf = []
        self._in_ld = False
        self._skip = 0
        self.words = Counter()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style", "noscript"):
            self._skip += 1
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name:
                self.metas[name] = a.get("content") or ""
        elif tag == "link":
            rel = (a.get("rel") or "").lower()
            if "canonical" in rel:
                self.canonical = a.get("href")
            if "icon" in rel:
                self.icon_link = True
        elif tag == "h1":
            self._in_h1 = True
            self._h1_buf = []
        elif tag == "h2":
            self.h2 += 1
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "img":
            self.img_total += 1
            if not (a.get("alt") or "").strip():
                self.img_no_alt += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False
        elif tag == "h1" and self._in_h1:
            self._in_h1 = False
            self.h1.append(" ".join("".join(self._h1_buf).split()))
        elif tag == "script":
            if self._in_ld:
                self._in_ld = False
                self.ldjson.append("".join(self._ldjson_buf))

    def handle_startendtag(self, tag, attrs):
        if tag == "img":
            a = dict(attrs)
            self.img_total += 1
            if not (a.get("alt") or "").strip():
                self.img_no_alt += 1

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._in_h1:
            self._h1_buf.append(data)
        if self._skip:
            # внутри <script> ловим application/ld+json
            if self._in_ld:
                self._ldjson_buf.append(data)
            return
        for w in re.findall(r"[а-яёa-z0-9\-]{3,}", data.lower()):
            if w not in STOPWORDS:
                self.words[w] += 1


class LdJsonParser(HTMLParser):
    """Ловит блоки <script type="application/ld+json"> до запуска PageParser
    не нужно — PageParser их не видит из-за _skip, поэтому отдельный проход."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.buf = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and "ld+json" in (a.get("type") or ""):
            self._cur = []

    def handle_endtag(self, tag):
        if tag == "script" and self._cur is not None:
            self.buf.append("".join(self._cur))
            self._cur = None

    def handle_data(self, data):
        if self._cur is not None:
            self._cur.append(data)


def parse_page(html_text):
    p = PageParser()
    try:
        p.feed(html_text)
        p.close()
    except Exception:
        pass
    ld = LdJsonParser()
    try:
        ld.feed(html_text)
        ld.close()
    except Exception:
        pass
    low = html_text.lower()
    counters = {
        "metrika": ("mc.yandex.ru" in low or "ym(" in low),
        "ga_gtm": ("googletagmanager.com" in low or "google-analytics.com" in low
                   or "gtag(" in low),
        "mail_ru_counter": "top-fwz1.mail.ru" in low,
    }
    ld_types = []
    for block in ld.buf:
        try:
            data = json.loads(block)
        except Exception:
            ld_types.append("(битый JSON)")
            continue
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                t = node.get("@type")
                if isinstance(t, str):
                    ld_types.append(t)
                elif isinstance(t, list):
                    ld_types.extend(str(x) for x in t)
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    return p, ld_types, counters


# ------------------------------------------------------------------- helpers

def normalize(url, keep_query=True):
    u = urllib.parse.urlsplit(url)
    host = (u.hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    if u.port:
        netloc = "%s:%d" % (host, u.port)
    else:
        netloc = host
    path = u.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = u.query if keep_query else ""
    return urllib.parse.urlunsplit((u.scheme, netloc, path, query, ""))


def same_host(url, base_host):
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    return host == base_host or host.endswith("." + base_host)


def strip_utm(url):
    u = urllib.parse.urlsplit(url)
    pairs = [p for p in u.query.split("&")
             if p and not p.lower().startswith(("utm_", "yclid", "gclid", "_openstat"))]
    return urllib.parse.urlunsplit((u.scheme, u.netloc, u.path,
                                    "&".join(pairs), ""))


def ssl_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(__import__("socket").create_connection(
                (hostname, 443), timeout=10), server_hostname=hostname) as s:
            cert = s.getpeercert()
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.datetime.utcnow()).days
            return {"expires": not_after, "days_left": days}
    except Exception as e:
        return {"error": str(e)}
    return {}


# --------------------------------------------------------------- site checks

def load_robots(base):
    rp = urllib.robotparser.RobotFileParser()
    robots_url = base + "/robots.txt"
    raw = None
    resp = fetch(robots_url)
    if resp["status"] == 200:
        raw = decode_body(resp)
    rp.parse(raw.splitlines() if raw is not None else [])
    sitemaps, host_hint = [], None
    if raw:
        for line in raw.splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
            elif low.startswith("host:") and host_hint is None:
                host_hint = line.split(":", 1)[1].strip()
    return rp, robots_url, resp["status"], raw, sitemaps, host_hint


def load_sitemap(base, sitemap_urls):
    """Возвращает (urls, stats). Читает индексы sitemap вглубь до 5 уровней."""
    urls, stats = [], {"files": 0, "index_files": 0, "with_lastmod": 0,
                       "stale_lastmod": 0, "errors": []}
    seen_files = set()
    queue = deque(sitemap_urls or [base + "/sitemap.xml"])
    while queue and len(seen_files) < 30:
        sm = queue.popleft()
        if sm in seen_files:
            continue
        seen_files.add(sm)
        resp = fetch(sm)
        if resp["status"] != 200:
            if len(seen_files) == 1:
                stats["errors"].append("%s -> HTTP %s" % (sm, resp["status"] or "err"))
                # пробуем индекс по стандартному имени
                alt = base + "/sitemap_index.xml"
                if resp["status"] != 200 and alt != sm:
                    queue.append(alt)
            else:
                stats["errors"].append("%s -> HTTP %s" % (sm, resp["status"] or "err"))
            continue
        try:
            root = ET.fromstring(resp["body"])
        except ET.ParseError as e:
            stats["errors"].append("%s -> битый XML: %s" % (sm, e))
            continue
        is_index = root.tag.lower().endswith("sitemapindex")
        locs = [el.text.strip() for el in root.iter()
                if el.tag.lower().endswith("loc") and el.text]
        lasts = [el.text.strip() for el in root.iter()
                 if el.tag.lower().endswith("lastmod") and el.text]
        if is_index:
            stats["index_files"] += 1
            for loc in locs[:30]:
                if same_host(loc, urllib.parse.urlsplit(base).hostname or ""):
                    queue.append(loc)
                else:
                    stats["errors"].append("внешний sitemap: %s" % loc)
        else:
            stats["files"] += 1
            now = datetime.datetime.now(datetime.timezone.utc)
            for lm in lasts:
                stats["with_lastmod"] += 1
                try:
                    d = datetime.datetime.fromisoformat(
                        lm.replace("Z", "+00:00")).replace(tzinfo=None)
                    if (now.replace(tzinfo=None) - d).days > 365:
                        stats["stale_lastmod"] += 1
                except ValueError:
                    pass
            urls.extend(locs)
    stats["urls"] = len(urls)
    stats["unique_urls"] = len(set(urls))
    return urls, stats


def site_checks(url, out):
    base = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(url))
    host = urllib.parse.urlsplit(url).hostname
    bare = host[4:] if host.startswith("www.") else host
    issues = []
    ok = []

    # главная
    home = fetch(base if not url.startswith("http://www") else url)
    if home["error"] and home["status"] == 0:
        die("сайт недоступен: %s (%s)" % (url, home["error"]))
    if home["chain"] and home["chain"][0][0] != home["chain"][-1][0]:
        ok.append("Главная: %s -> редирект на %s" % (home["chain"][0][0], home["final"]))
    if home["status"] == 200:
        ok.append("Главная отвечает 200 (%.2f c)" % home["elapsed"])
    else:
        issues.append("Главная отвечает HTTP %s" % home["status"])

    is_https = urllib.parse.urlsplit(url).scheme == "https"
    if is_https:
        # http -> https
        http_home = fetch(base.replace("https://", "http://", 1))
        if http_home["status"] in (301, 302, 308) or (
                http_home["chain"] and http_home["final"].startswith("https")):
            ok.append("HTTP -> HTTPS: редирект есть")
        else:
            issues.append("HTTP не редиректит на HTTPS (статус %s)" % http_home["status"])
        cert = ssl_info(bare)
        if "days_left" in cert:
            if cert["days_left"] < 14:
                issues.append("SSL-сертификат истекает через %s дн. (%s)"
                              % (cert["days_left"], cert["expires"]))
            else:
                ok.append("SSL: действует, ещё %s дн." % cert["days_left"])
        elif "error" in cert:
            issues.append("SSL: не удалось получить сертификат: %s" % cert["error"])
    else:
        issues.append("Сайт работает по HTTP без HTTPS")

    # зеркала www / без www
    for variant in ("https://%s/" % bare, "https://www.%s/" % bare):
        r = fetch(variant)
        if r["status"] == 0:
            continue
        redir = r["status"] in (301, 302, 308)
        if not redir and r["status"] == 200 and normalize(r["final"]) != normalize(home["final"]):
            issues.append("Зеркало %s отвечает 200 без редиректа (дубль)" % variant)
    ok.append("Зеркала: проверены www/не-www")

    # robots.txt
    rp, robots_url, robots_status, robots_raw, sitemaps, host_hint = load_robots(base)
    if robots_status == 200:
        ok.append("robots.txt найден (%d байт)" % len(robots_raw or ""))
        if not rp.can_fetch(UA, base + "/"):
            issues.append("robots.txt запрещает индексацию главной для User-Agent")
        if sitemaps:
            ok.append("Sitemap в robots.txt: %s" % ", ".join(sitemaps[:3]))
        else:
            issues.append("В robots.txt не указана директива Sitemap")
    elif robots_status == 404:
        issues.append("robots.txt отсутствует (404)")
    else:
        issues.append("robots.txt: HTTP %s" % robots_status)

    # sitemap
    sm_urls, sm_stats = load_sitemap(base, sitemaps)
    if sm_urls:
        ok.append("sitemap: %d URL, %d файлов, lastmod у %d, устаревших (>1 года) %d"
                  % (sm_stats["unique_urls"], sm_stats["files"],
                     sm_stats["with_lastmod"], sm_stats["stale_lastmod"]))
        if sm_stats["stale_lastmod"] and sm_stats["with_lastmod"] \
                and sm_stats["stale_lastmod"] == sm_stats["with_lastmod"]:
            issues.append("Все lastmod в sitemap старше года")
        blocked = [u for u in set(sm_urls) if not rp.can_fetch(UA, u)]
        if blocked:
            issues.append("robots.txt блокирует %d URL из sitemap (пример: %s)"
                          % (len(blocked), blocked[0]))
    else:
        issues.append("sitemap.xml не найден или пуст: %s" % "; ".join(sm_stats["errors"][:2]))

    # 404
    miss = fetch(base + "/seo-audit-check-nonexistent-%d/" % int(time.time()))
    if miss["status"] == 404:
        ok.append("Несуществующая страница отдаёт 404")
    elif miss["status"] == 200:
        issues.append("Несуществующая страница отдаёт 200 (soft-404)")
    else:
        issues.append("Несуществующая страница отдаёт HTTP %s" % miss["status"])

    # favicon
    fav = fetch(base + "/favicon.ico", method="GET")
    home_html = decode_body(home) if home["status"] == 200 else ""
    has_favicon = fav["status"] == 200 or (home_html and 'rel="icon"' in home_html
                                           or "rel='icon'" in home_html)
    if has_favicon:
        ok.append("favicon есть")
    else:
        issues.append("favicon не найден")

    # мета главной + скорость
    if home_html:
        p, ld_types, counters = parse_page(home_html)
        if p.title:
            ok.append("Title главной: %r (%d зн.)" % (p.title.strip()[:70], len(p.title.strip())))
        else:
            issues.append("У главной пустой <title>")
        if not p.metas.get("description", "").strip():
            issues.append("У главной пустой description")
        if not p.h1:
            issues.append("У главной нет H1")
        if ld_types:
            ok.append("Микроразметка главной: %s" % ", ".join(sorted(set(ld_types))[:5]))
        else:
            issues.append("На главной нет JSON-LD микроразметки")
        if not (counters["metrika"] or counters["ga_gtm"]):
            issues.append("На главной не найден счётчик аналитики (Метрика/GA)")
        if not re.search(r'name=["\']viewport["\']', home_html):
            issues.append("На главной нет meta viewport (мобильная адаптивность под вопросом)")
    if home["elapsed"] > 2.0:
        issues.append("Главная отвечает медленно: %.2f c" % home["elapsed"])

    result = {"base": base, "ok": ok, "issues": issues,
              "sitemap_urls": sorted(set(sm_urls)),
              "robots_url": robots_url, "robots_status": robots_status,
              "sitemap_stats": sm_stats}
    return result


# ---------------------------------------------------------------------- crawl

def crawl(start_url, max_pages, delay, out_dir, respect_robots=True):
    start = strip_utm(start_url)
    u = urllib.parse.urlsplit(start)
    if not u.scheme or not u.hostname:
        die("нужен полный URL, например https://site.ru/")
    base_host = u.hostname.lower()
    base_host = base_host[4:] if base_host.startswith("www.") else base_host
    base = "{0.scheme}://{0.netloc}".format(u)

    rp = urllib.robotparser.RobotFileParser()
    rresp = fetch(base + "/robots.txt")
    rp.parse(decode_body(rresp).splitlines() if rresp["status"] == 200 else [])

    seen = set()
    queue = deque([normalize(start)])
    pages, broken, redirects = [], {}, {}
    external_checked = {}

    while queue and len(pages) < max_pages:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        if urllib.parse.urlsplit(url).path.lower().endswith(SKIP_EXT):
            continue
        if respect_robots and not rp.can_fetch(UA, url):
            pages.append({"url": url, "status": -1,
                          "note": "заблокировано в robots.txt"})
            continue
        resp = fetch(url)
        if resp["status"] == 0:
            broken.setdefault(url, {"status": 0, "error": resp["error"], "from": []})
            continue
        if resp["status"] >= 400:
            broken.setdefault(url, {"status": resp["status"], "from": []})
            continue
        if resp["final"] != resp["chain"][0][0]:
            redirects[url] = {"final": resp["final"],
                              "chain": ["%s->%s" % (a, b) for a, b in resp["chain"]]}
            norm_final = normalize(resp["final"])
            if norm_final not in seen:
                queue.append(norm_final)
            continue
        ctype = resp["headers"].get("Content-Type", "")
        if "html" not in ctype.lower():
            continue

        html_text = decode_body(resp)
        p, ld_types, counters = parse_page(html_text)
        title = p.title.strip()
        meta_robots = p.metas.get("robots", "")
        x_robots = resp["headers"].get("X-Robots-Tag", "")
        words_total = sum(p.words.values())
        page = {
            "url": url,
            "status": resp["status"],
            "elapsed": resp["elapsed"],
            "html_size": len(resp["body"]),
            "title": title,
            "title_len": len(title),
            "description": (p.metas.get("description") or "").strip(),
            "h1": p.h1,
            "h2_count": p.h2,
            "canonical": p.canonical,
            "meta_robots": meta_robots,
            "x_robots_tag": x_robots,
            "words_total": words_total,
            "top_words": p.words.most_common(15),
            "ldjson_types": sorted(set(ld_types)),
            "ldjson_broken": "(битый JSON)" in ld_types,
            "img_total": p.img_total,
            "img_no_alt": p.img_no_alt,
            "counters": counters,
            "viewport": 'name="viewport"' in html_text or "name='viewport'" in html_text,
            "icon_link": p.icon_link,
        }
        pages.append(page)

        for href in p.links:
            link = strip_utm(urllib.parse.urljoin(url, href))
            nu = normalize(link)
            if nu.startswith("mailto:") or nu.startswith("tel:") or nu.startswith("javascript:"):
                continue
            if same_host(link, base_host):
                if nu not in seen:
                    queue.append(nu)
            else:
                # внешние ссылки проверяем лениво, максимум 100 штук
                if len(external_checked) < 100 and link not in external_checked:
                    r = fetch(link, method="HEAD")
                    if r["status"] == 0 or r["status"] >= 400:
                        r = fetch(link)
                    external_checked[link] = r["status"] or -1
        time.sleep(delay)

    # от кого ссылались битые (по страницам с данными — второй проход по HTML не делаем,
    # источники собираем из краула ниже)
    os.makedirs(out_dir, exist_ok=True)
    data = {"start": start, "base": base, "crawled": len(pages),
            "max_pages": max_pages, "pages": pages,
            "broken": broken, "redirects": redirects,
            "external": external_checked,
            "fetched_at": datetime.datetime.now().isoformat(timespec="seconds")}
    path = os.path.join(out_dir, "pages.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    print("Обошли %d страниц -> %s" % (len(pages), path))
    print("Битых: %d, внутренних редиректов: %d, внешних проверено: %d"
          % (len(broken), len(redirects), len(external_checked)))
    return data


# --------------------------------------------------------------------- report

def plural(n, one, few, many):
    n10, n100 = n % 10, n % 100
    if 10 <= n100 <= 20:
        return "%d %s" % (n, many)
    if n10 == 1:
        return "%d %s" % (n, one)
    if 2 <= n10 <= 4:
        return "%d %s" % (n, few)
    return "%d %s" % (n, many)


def _dup_map(pages, key):
    m = {}
    for p in pages:
        v = p.get(key) or ""
        if isinstance(v, list):
            v = " | ".join(v)
        v = v.strip().lower()
        if v:
            m.setdefault(v, []).append(p["url"])
    return {k: v for k, v in m.items() if len(v) > 1}


def build_report(data, out_dir):
    pages = [p for p in data["pages"] if p.get("status", 0) > 0]
    blocked = [p for p in data["pages"] if p.get("status") == -1]
    issues = []  # (severity, category, page, problem)

    for url, info in (data.get("broken") or {}).items():
        txt = ("HTTP %s %s" % (info.get("status", ""), info.get("error", ""))).strip()
        issues.append(("critical", "битые ссылки", url, txt))
    for url, info in (data.get("redirects") or {}).items():
        issues.append(("warning", "редиректы", url, "-> %s" % info["final"]))
    for url, st in (data.get("external") or {}).items():
        if st >= 400 or st == -1:
            issues.append(("warning", "внешние ссылки", url, "HTTP %s" % st))

    for p in blocked:
        issues.append(("warning", "robots.txt", p["url"],
                       "страница заблокирована robots.txt — проверь, целевая ли она"))

    dup_title = _dup_map(pages, "title")
    for t, urls in dup_title.items():
        issues.append(("warning", "дубли title", ", ".join(urls[:4]),
                       "одинаковый title (%d стр.): %r" % (len(urls), t[:50])))
    dup_desc = _dup_map(pages, "description")
    for d, urls in dup_desc.items():
        issues.append(("warning", "дубли description", ", ".join(urls[:4]),
                       "одинаковый description (%d стр.)" % len(urls)))
    dup_h1 = _dup_map(pages, "h1")
    for h, urls in dup_h1.items():
        issues.append(("warning", "дубли H1", ", ".join(urls[:4]),
                       "одинаковый H1 (%d стр.)" % len(urls)))

    for p in pages:
        u = p["url"]
        if not p["title"]:
            issues.append(("critical", "мета-теги", u, "пустой <title>"))
        elif p["title_len"] < 10:
            issues.append(("warning", "мета-теги", u,
                           "title короче 10 знаков: %r" % p["title"]))
        elif p["title_len"] > 75:
            issues.append(("info", "мета-теги", u,
                           "title длиннее 75 знаков (%d)" % p["title_len"]))
        if not p["description"]:
            issues.append(("warning", "мета-теги", u, "пустой description"))
        elif len(p["description"]) > 250:
            issues.append(("info", "мета-теги", u,
                           "description длиннее 250 знаков (%d)" % len(p["description"])))
        if not p["h1"]:
            issues.append(("warning", "мета-теги", u, "нет H1"))
        elif len(p["h1"]) > 1:
            issues.append(("info", "мета-теги", u, "H1 больше одного (%d)" % len(p["h1"])))
        robots_low = (p.get("meta_robots", "") + " " + p.get("x_robots_tag", "")).lower()
        if "noindex" in robots_low:
            issues.append(("warning", "индексация", u,
                           "noindex (meta/x-robots): %r" % p["meta_robots"]))
        if p.get("canonical"):
            cu = normalize(urllib.parse.urljoin(u, p["canonical"]))
            if cu != normalize(u):
                issues.append(("info", "индексация", u, "canonical -> %s" % cu))
        if p["words_total"] < 100:
            issues.append(("warning", "контент", u,
                           "мало текста: %s" % plural(p["words_total"], "слово", "слова", "слов")))
        if p["top_words"] and p["title"]:
            top_word = p["top_words"][0][0]
            title_low = p["title"].lower()
            if top_word not in title_low and top_word[:3] not in title_low:
                issues.append(("info", "контент", u,
                               "самое частое слово %r не встречается в title "
                               "(проверь релевантность)" % top_word))
        if not p["ldjson_types"]:
            issues.append(("info", "разметка", u, "нет JSON-LD микроразметки"))
        if p.get("ldjson_broken"):
            issues.append(("warning", "разметка", u, "битый JSON-LD"))
        cnt = p.get("counters") or {}
        if not (cnt.get("metrika") or cnt.get("ga_gtm")):
            issues.append(("warning", "аналитика", u, "нет счётчика (Метрика/GA)"))
        if p["img_no_alt"] and p["img_no_alt"] >= max(3, p["img_total"] * 0.3):
            issues.append(("info", "контент", u,
                           "%d/%d изображений без alt" % (p["img_no_alt"], p["img_total"])))
        if not p.get("viewport"):
            issues.append(("critical", "мобильность", u, "нет meta viewport"))
        if p["elapsed"] > 2.0:
            issues.append(("warning", "скорость", u,
                           "медленный ответ: %.2f c" % p["elapsed"]))
        path_ = urllib.parse.urlsplit(u).path
        u_ = urllib.parse.unquote(u)
        problems = []
        if re.search(r"%D[0-9A-F]|%[89A-F][0-9A-F]", urllib.parse.urlsplit(u).query + path_, re.I) \
                or re.search(r"[а-яё]", urllib.parse.unquote(path_)):
            problems.append("кириллица в URL")
        if len(u_) > 120:
            problems.append("URL длиннее 120 символов (%d)" % len(u_))
        if path_.count("/") > 5:
            problems.append("глубокая вложенность (%d уровней)" % path_.count("/") - 1)
        if "index.php" in path_ or path_.endswith((".html", ".htm", ".php", ".aspx")):
            problems.append("статическое окончание URL")
        if urllib.parse.urlsplit(u).query:
            problems.append("параметры в URL")
        for pr in problems:
            issues.append(("info", "URL", u, pr))

    # sitemap vs crawl
    sitemap_urls = data.get("sitemap_urls")
    if sitemap_urls:
        crawled = {normalize(p["url"]) for p in pages}
        in_sitemap = {normalize(x) for x in sitemap_urls}
        missing = in_sitemap - crawled
        if missing:
            issues.append(("warning", "sitemap", ", ".join(sorted(missing)[:5]),
                           "%d URL из sitemap не найдены краулером "
                           "(возможно закрыты от обхода или битые)" % len(missing)))

    sev_order = {"critical": 0, "warning": 1, "info": 2}
    issues.sort(key=lambda x: (sev_order[x[0]], x[1], x[2]))
    by_cat = Counter(i[1] for i in issues)
    by_sev = Counter(i[0] for i in issues)

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "issues.csv"), "w", encoding="utf-8-sig",
              newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["важность", "категория", "страница", "проблема"])
        w.writerows(issues)

    lines = ["# Сводка локального аудита", "",
             "- Сайт: %s" % data.get("base", ""),
             "- Обошли страниц: %s (лимит %s)" % (data.get("crawled"), data.get("max_pages", "-")),
             "- Проблемы: критичных %d, предупреждений %d, замечаний %d"
             % (by_sev.get("critical", 0), by_sev.get("warning", 0), by_sev.get("info", 0)),
             "- Дата: %s" % data.get("fetched_at", ""), ""]
    if by_cat:
        lines += ["## Проблемы по категориям", "",
                  "| Категория | Кол-во |", "|---|---|"]
        for cat, n in by_cat.most_common():
            lines.append("| %s | %d |" % (cat, n))
        lines.append("")
    for sev, title in (("critical", "Критичные"), ("warning", "Предупреждения"),
                       ("info", "Замечания")):
        rows = [i for i in issues if i[0] == sev]
        if not rows:
            continue
        lines += ["## %s (%d)" % (title, len(rows)), ""]
        for _, cat, page, problem in rows:
            lines.append("- **%s** — %s: %s" % (cat, page, problem))
        lines.append("")
    lines += ["Полные данные: pages.json; список проблем: issues.csv. "
              "Пороги (длины мета-тегов, скорость) — эвристики, а не официальные лимиты."]
    summary = os.path.join(out_dir, "summary.md")
    with open(summary, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("Сводка -> %s; проблемы -> issues.csv" % summary)
    print("Критичных: %d, предупреждений: %d, замечаний: %d"
          % (by_sev.get("critical", 0), by_sev.get("warning", 0), by_sev.get("info", 0)))
    return summary


# ----------------------------------------------------------------------- urls

def check_urls(input_path, out_dir):
    if not os.path.isfile(input_path):
        die("нет файла %s" % input_path)
    urls = []
    with open(input_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    rows = []
    for u in urls:
        if not urllib.parse.urlsplit(u).scheme:
            u = "https://" + u
        r = fetch(u)
        row = {"url": u, "status": r["status"], "final": r["final"],
               "redirects": len(r["chain"]) - 1, "error": r["error"] or ""}
        if r["status"] == 200 and "html" in r["headers"].get("Content-Type", "").lower():
            p, ld, _ = parse_page(decode_body(r))
            row.update({"title": p.title.strip(),
                        "description": (p.metas.get("description") or "").strip(),
                        "h1": " | ".join(p.h1), "meta_robots": p.metas.get("robots", ""),
                        "canonical": p.canonical or "",
                        "ldjson": ",".join(sorted(set(ld)))})
        rows.append(row)
        print("%s %s %s" % (r["status"], u, "-> " + r["final"] if row["redirects"] else ""))
        time.sleep(0.3)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "urls_report.csv"), "w",
              encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "url", "status", "final", "redirects", "error", "title",
            "description", "h1", "meta_robots", "canonical", "ldjson"],
            delimiter=";")
        w.writeheader()
        w.writerows(rows)
    print("Отчёт -> %s/urls_report.csv" % out_dir)


# ----------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Локальный технический SEO-аудит (stdlib only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--out", default="site-audit", help="каталог результатов")
        p.add_argument("--timeout", type=int, default=TIMEOUT)

    p_audit = sub.add_parser("audit", help="полный аудит: site + crawl + report")
    p_audit.add_argument("url")
    p_audit.add_argument("--max-pages", type=int, default=100)
    p_audit.add_argument("--delay", type=float, default=0.5)
    common(p_audit)

    p_site = sub.add_parser("site", help="проверки уровня сайта")
    p_site.add_argument("url")
    common(p_site)

    p_crawl = sub.add_parser("crawl", help="обход сайта")
    p_crawl.add_argument("url")
    p_crawl.add_argument("--max-pages", type=int, default=100)
    p_crawl.add_argument("--delay", type=float, default=0.5)
    common(p_crawl)

    p_rep = sub.add_parser("report", help="сводка по pages.json")
    p_rep.add_argument("file", help="путь к pages.json")
    common(p_rep)

    p_urls = sub.add_parser("urls", help="точечная проверка списка URL")
    p_urls.add_argument("--input", required=True, help="файл со списком URL")
    common(p_urls)

    args = ap.parse_args()
    if args.cmd == "audit":
        site = site_checks(args.url, args.out)
        data = crawl(args.url, args.max_pages, args.delay, args.out)
        data["sitemap_urls"] = site["sitemap_urls"]
        with open(os.path.join(args.out, "pages.json"), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        with open(os.path.join(args.out, "site_report.md"), "w", encoding="utf-8") as f:
            f.write("# Проверки уровня сайта: %s\n\n## Ок\n%s\n\n## Проблемы\n%s\n"
                    % (site["base"], "\n".join("- " + x for x in site["ok"]) or "-",
                       "\n".join("- " + x for x in site["issues"]) or "-"))
        print("\n== Сайт: проблем %d, ок %d ==" % (len(site["issues"]), len(site["ok"])))
        build_report(data, args.out)
        print("\nИтоги: site_report.md, summary.md, issues.csv, pages.json в %s" % args.out)
    elif args.cmd == "site":
        site = site_checks(args.url, args.out)
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "site_report.md"), "w", encoding="utf-8") as f:
            f.write("# Проверки уровня сайта: %s\n\n## Ок\n%s\n\n## Проблемы\n%s\n"
                    % (site["base"], "\n".join("- " + x for x in site["ok"]) or "-",
                       "\n".join("- " + x for x in site["issues"]) or "-"))
        for x in site["issues"]:
            print("ПРОБЛЕМА:", x)
        for x in site["ok"]:
            print("ок:", x)
    elif args.cmd == "crawl":
        crawl(args.url, args.max_pages, args.delay, args.out)
    elif args.cmd == "report":
        with open(args.file, encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("sitemap_urls", [])
        build_report(data, args.out)
    elif args.cmd == "urls":
        check_urls(args.input, args.out)


if __name__ == "__main__":
    main()
