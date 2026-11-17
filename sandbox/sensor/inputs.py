"""Where the sensor gets lines from: on-host file tail, off-host syslog, or inline as a logging reverse proxy.

  file     tail one or more access logs (rotation-aware: by inode + size; picks up `access.log` after rotation)
  syslog   listen on UDP and TCP :5514 (RFC 3164/5424 framing stripped; the message part is the access-log line)
           Caddy:   log { output net udp/sensor-host:5514 }      nginx:  access_log syslog:server=sensor-host:5514 combined;
  inline   a tiny reverse proxy: listens on :8080, forwards to SENSOR_UPSTREAM, logs each request as a Caddy-style
           JSON entry into the same pipeline. Not for production TLS termination; it sits BEHIND your proxy or in
           front of one app. Streams bodies; never buffers more than 1 MiB.

Every input yields (line:str, source:str). The run loop parses and aggregates.
"""
from __future__ import annotations

import http.server
import json
import os
import re
import socket
import socketserver
import threading
import time
import urllib.request
from typing import Callable, Iterable, List

SYSLOG_RE = re.compile(r"^(?:<\d{1,3}>)?(?:\d\s)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s[\d:]{8}\s|\d{4}-\d{2}-\d{2}T[^\s]+\s)?(?:\S+\s)?(?:[\w./-]+(?:\[\d+\])?:\s)?(?:-\s-\s-\s)?")


def strip_syslog(msg: str) -> str:
    """Drop PRI / timestamp / host / tag framing; what is left is the access-log line."""
    s = msg.strip()
    m = SYSLOG_RE.match(s)
    body = s[m.end():] if m else s
    # nginx syslog puts the tag before the line: "nginx: 1.2.3.4 - - [...]"; Caddy net output is the raw JSON
    i = body.find("{")
    if i > 0 and body[i:].rstrip().endswith("}"):
        return body[i:]
    return body


class FileTail:
    """Tail files by path; remembers inode + offset so rotation never double-counts or skips."""

    def __init__(self, paths: List[str], state: dict):
        self.paths = paths
        self.state = state.setdefault("tail", {})

    def read_new(self) -> Iterable[tuple]:
        for p in self.paths:
            try:
                st = os.stat(p)
            except OSError:
                continue
            key = p
            s = self.state.get(key) or {}
            if s.get("inode") != st.st_ino or s.get("offset", 0) > st.st_size:
                s = {"inode": st.st_ino, "offset": 0}
            try:
                with open(p, "rb") as f:
                    f.seek(s["offset"])
                    buf = f.read(8 << 20)
            except OSError:
                continue
            if not buf:
                self.state[key] = s
                continue
            cut = buf.rfind(b"\n")
            if cut == -1:
                self.state[key] = s
                continue
            s["offset"] += cut + 1
            self.state[key] = s
            for raw in buf[:cut].split(b"\n"):
                if raw:
                    yield raw.decode("utf-8", "replace"), os.path.basename(p)


class SyslogServer:
    def __init__(self, on_line: Callable[[str, str], None], port: int = 5514):
        self.on_line, self.port = on_line, port
        self.udp: socket.socket | None = None
        self.threads: List[threading.Thread] = []

    def start(self) -> None:
        on_line = self.on_line

        def udp():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("0.0.0.0", self.port))
            self.udp = s
            while True:
                data, addr = s.recvfrom(65535)
                for ln in data.decode("utf-8", "replace").splitlines():
                    if ln.strip():
                        on_line(strip_syslog(ln), f"syslog-udp:{addr[0]}")

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                for raw in self.rfile:
                    ln = raw.decode("utf-8", "replace")
                    if ln.strip():
                        on_line(strip_syslog(ln), f"syslog-tcp:{self.client_address[0]}")

        class TCP(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        srv = TCP(("0.0.0.0", self.port), H)
        for target in (udp, srv.serve_forever):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self.threads.append(t)


class InlineProxy:
    """Logging reverse proxy. SENSOR_UPSTREAM=http://app:3000 ; listens on :8080 ; emits Caddy-shaped JSON lines."""

    def __init__(self, on_line: Callable[[str, str], None], upstream: str, port: int = 8080):
        self.on_line, self.upstream, self.port = on_line, upstream.rstrip("/"), port

    def start(self) -> None:
        on_line, upstream = self.on_line, self.upstream

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # quiet
                pass

            def _do(self):
                t0 = time.time()
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(min(length, 1 << 20)) if length else None
                url = upstream + self.path
                hdrs = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "content-length")}
                hdrs["X-Forwarded-For"] = (self.headers.get("X-Forwarded-For") + ", " if self.headers.get("X-Forwarded-For") else "") + self.client_address[0]
                status, size = 502, 0
                try:
                    req = urllib.request.Request(url, data=body, headers=hdrs, method=self.command)
                    with urllib.request.urlopen(req, timeout=30) as r:
                        status = r.status
                        data = r.read()
                        size = len(data)
                        self.send_response(status)
                        for k, v in r.headers.items():
                            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                                self.send_header(k, v)
                        self.send_header("Content-Length", str(size))
                        self.end_headers()
                        self.wfile.write(data)
                except urllib.error.HTTPError as e:
                    status = e.code
                    data = e.read()
                    size = len(data)
                    self.send_response(status)
                    self.send_header("Content-Length", str(size))
                    self.end_headers()
                    self.wfile.write(data)
                except Exception:  # noqa: BLE001
                    self.send_response(502)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                client_ip = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or self.client_address[0]
                entry = {"ts": t0, "duration": round(time.time() - t0, 4), "status": status, "size": size,
                         "request": {"remote_ip": self.client_address[0], "client_ip": client_ip, "method": self.command, "host": self.headers.get("Host", ""),
                                     "uri": self.path, "headers": {"User-Agent": [self.headers.get("User-Agent", "")], "Referer": [self.headers.get("Referer", "")]}}}
                on_line(json.dumps(entry), "inline")

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = do_PATCH = _do

        class S(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        srv = S(("0.0.0.0", self.port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
