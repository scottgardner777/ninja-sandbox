"""Access-log parsers -> one flat request dict per line.

    {"ts": epoch float, "ip": client ip, "host": site, "method", "uri", "path", "status": int, "size": int,
     "user_agent", "referer", "cc": country code if the proxy supplies one, "raw_len": len(line)}

Formats: caddy (JSON, one object per line; honours Cf-Connecting-Ip / X-Forwarded-For), nginx and apache
("combined" and "combined + vhost" and the common "$host" prefix variant), traefik (JSON access log).
`auto` sniffs per line. Unparseable lines return None and are counted by the caller.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Optional

# 1.2.3.4 - - [17/Nov/2026:11:02:03 +0000] "GET /x HTTP/1.1" 404 153 "-" "curl/8.0"           (combined)
# example.com 1.2.3.4 - - [..] "GET ..." 404 153 "-" "UA"                                      (vhost_combined)
COMBINED_RE = re.compile(
    r'^(?:(?P<vhost>[A-Za-z0-9.\-:_]+)\s+)?(?P<ip>[0-9a-fA-F.:]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)?\s*(?P<uri>[^"\s]*)(?:\s+(?P<proto>HTTP/[0-9.]+))?"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?(?:\s+"?(?P<xff>[0-9a-fA-F.:, ]+|-)"?)?')
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def _first(v):
    if isinstance(v, list):
        return v[0] if v else ""
    return v or ""


def _clf_time(s: str) -> float:
    # 17/Nov/2026:11:02:03 +0000
    try:
        d, mon, rest = s.split("/", 2)
        y, hh, mm, ss_tz = rest.split(":", 3)
        ss, tz = ss_tz.split(" ", 1)
        sign = 1 if tz[0] == "+" else -1
        off = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
        dt = datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
        return dt.timestamp() - off
    except (ValueError, KeyError, IndexError):
        return time.time()


def parse_caddy(line: str) -> Optional[dict]:
    try:
        d = json.loads(line)
    except ValueError:
        return None
    req = d.get("request")
    if not isinstance(req, dict):
        return None
    h = req.get("headers") or {}
    ip = _first(h.get("Cf-Connecting-Ip")) or _first(h.get("X-Forwarded-For")).split(",")[0].strip() or req.get("client_ip") or req.get("remote_ip") or ""
    uri = req.get("uri") or "/"
    try:
        ts = float(d.get("ts") or 0) or time.time()
    except (TypeError, ValueError):
        ts = time.time()
    return {"ts": ts, "ip": ip, "host": (req.get("host") or "").split(":")[0].lower()[:80], "method": req.get("method") or "GET",
            "uri": uri[:2000], "path": uri.split("?")[0][:1000], "status": int(d.get("status") or 0), "size": int(d.get("size") or 0),
            "user_agent": _first(h.get("User-Agent"))[:300], "referer": _first(h.get("Referer"))[:300],
            "cc": (_first(h.get("Cf-Ipcountry")) or "").upper()[:2], "raw_len": len(line)}


def parse_traefik(line: str) -> Optional[dict]:
    try:
        d = json.loads(line)
    except ValueError:
        return None
    if "RequestPath" not in d and "RequestHost" not in d:
        return None
    ip = (d.get("ClientHost") or d.get("ClientAddr") or "").split(":")[0]
    xff = d.get("request_X-Forwarded-For") or ""
    if xff:
        ip = xff.split(",")[0].strip()
    ts = time.time()
    try:
        ts = datetime.fromisoformat(d.get("StartUTC", "").replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        pass
    uri = d.get("RequestPath") or "/"
    return {"ts": ts, "ip": ip, "host": (d.get("RequestHost") or "").split(":")[0].lower()[:80], "method": d.get("RequestMethod") or "GET",
            "uri": uri[:2000], "path": uri.split("?")[0][:1000], "status": int(d.get("DownstreamStatus") or d.get("OriginStatus") or 0),
            "size": int(d.get("DownstreamContentSize") or 0), "user_agent": (d.get("request_User-Agent") or "")[:300],
            "referer": (d.get("request_Referer") or "")[:300], "cc": "", "raw_len": len(line)}


def parse_combined(line: str) -> Optional[dict]:
    m = COMBINED_RE.match(line.strip())
    if not m:
        return None
    ip = m.group("ip")
    xff = m.group("xff")
    if xff and xff != "-":
        ip = xff.split(",")[0].strip()
    uri = m.group("uri") or "/"
    size = m.group("size")
    return {"ts": _clf_time(m.group("time")), "ip": ip, "host": (m.group("vhost") or "").split(":")[0].lower()[:80],
            "method": m.group("method") or "GET", "uri": uri[:2000], "path": uri.split("?")[0][:1000], "status": int(m.group("status")),
            "size": int(size) if size and size != "-" else 0, "user_agent": (m.group("ua") or "")[:300],
            "referer": (m.group("referer") or "")[:300], "cc": "", "raw_len": len(line)}


PARSERS = {"caddy": parse_caddy, "nginx": parse_combined, "apache": parse_combined, "combined": parse_combined, "traefik": parse_traefik}


def parse(line: str, fmt: str = "auto") -> Optional[dict]:
    line = line.strip()
    if not line:
        return None
    if fmt in PARSERS:
        return PARSERS[fmt](line)
    if line[0] == "{":
        return parse_caddy(line) or parse_traefik(line)
    return parse_combined(line)
