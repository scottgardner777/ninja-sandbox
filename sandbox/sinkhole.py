#!/usr/bin/env python3
"""The cell's sinkhole: the only thing a detonated sample can talk to.

Runs in its own container on the internal (no-egress) cell network with NET_ADMIN so iptables can redirect
EVERY TCP destination to :9999 and every UDP/53 to :5353. It then:
  - answers every DNS question with its own address (so the bot "resolves" its C2 and connects here),
  - accepts every TCP connection, recovers the ORIGINAL destination ip:port via SO_ORIGINAL_DST, reads up to
    2 KiB of what the bot sends, replies with a protocol-appropriate banner, and logs one JSON line,
  - captures everything on the wire with tcpdump to /out/capture.pcap (the pcap the Reverse tab offers).
Nothing leaves the network; nothing is executed here. Output: /out/sinkhole.jsonl, /out/capture.pcap

Standalone file on purpose: it is bind-mounted into the sinkhole image and has no imports from the package.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

OUT = "/out/sinkhole.jsonl"
PCAP = "/out/capture.pcap"
SO_ORIGINAL_DST = 80
lock = threading.Lock()


def log(rec):
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S.", time.gmtime()) + f"{int((time.time() % 1) * 1000):03d}Z"
    with lock, open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def my_ip():
    return os.environ.get("SINK_IP") or socket.gethostbyname(socket.gethostname())


def iptables():
    for cmd in (["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-ports", "9999"],
                ["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5353"],
                ["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "!", "--dport", "53", "-j", "REDIRECT", "--to-ports", "9998"]):
        subprocess.run(cmd, check=False)


def tcpdump():
    try:
        subprocess.Popen(["tcpdump", "-i", "any", "-U", "-s", "0", "-w", PCAP, "not", "port", "22"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        log({"kind": "note", "note": "tcpdump not in image: no pcap"})


def dns_server(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 5353))
    while True:
        try:
            data, addr = s.recvfrom(1024)
            if len(data) < 12:
                continue
            i, labels = 12, []
            while i < len(data) and data[i] != 0:
                n = data[i]
                labels.append(data[i + 1:i + 1 + n].decode("latin1", "replace"))
                i += n + 1
            qname = ".".join(labels)
            qtype = struct.unpack(">H", data[i + 1:i + 3])[0] if len(data) >= i + 3 else 1
            qend = i + 5
            tid = data[:2]
            hdr = tid + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
            ans = b"\xc0\x0c" + b"\x00\x01\x00\x01" + struct.pack(">I", 30) + b"\x00\x04" + socket.inet_aton(ip)
            s.sendto(hdr + data[12:qend] + ans, addr)
            log({"kind": "dns", "src": addr[0], "qname": qname, "qtype": qtype, "answered": ip})
        except Exception as e:  # noqa: BLE001
            log({"kind": "dns_error", "error": type(e).__name__})


def udp_sink():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 9998))
    while True:
        try:
            data, addr = s.recvfrom(4096)
            log({"kind": "udp", "src": addr[0], "bytes": len(data), "head_hex": data[:128].hex(),
                 "head_text": data[:128].decode("latin1", "replace").replace("\r", "\\r").replace("\n", "\\n")})
        except Exception as e:  # noqa: BLE001
            log({"kind": "udp_error", "error": type(e).__name__})


def banner(port, head):
    if port in (80, 8080, 8000, 443, 8443, 81, 8081) or head[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI"):
        return b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    if port == 21:
        return b"220 FTP ready\r\n"
    if port in (23, 2323):
        return b"login: "
    if port == 22:
        return b"SSH-2.0-OpenSSH_8.9\r\n"
    if port in (6667, 6697) or head.upper().startswith((b"NICK", b"USER", b"PASS")):
        return b":irc.sinkhole NOTICE AUTH :*** Looking up your hostname...\r\n"
    if port == 25:
        return b"220 mail ready ESMTP\r\n"
    return b"\x00"


def handle(conn, addr):
    try:
        raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack(">H", raw[2:4])[0]
        dst = socket.inet_ntoa(raw[4:8])
    except Exception:
        dst, port = "?", 0
    conn.settimeout(4)
    head = b""
    try:
        head = conn.recv(2048)
    except Exception:
        pass
    try:
        conn.sendall(banner(port, head))
        conn.settimeout(3)
        try:
            more = conn.recv(2048)   # what it says after the banner: the second line of an IRC/telnet exchange
        except Exception:
            more = b""
    except Exception:
        more = b""
    finally:
        conn.close()
    log({"kind": "tcp", "src": addr[0], "dst": dst, "dport": port, "bytes": len(head) + len(more),
         "head_hex": head[:256].hex(),
         "head_text": head[:256].decode("latin1", "replace").replace("\r", "\\r").replace("\n", "\\n"),
         "after_banner": more[:160].decode("latin1", "replace").replace("\r", "\\r").replace("\n", "\\n")})


def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 9999))
    s.listen(256)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    os.makedirs("/out", exist_ok=True)
    ip = my_ip()
    iptables()
    tcpdump()
    log({"kind": "start", "ip": ip})
    threading.Thread(target=dns_server, args=(ip,), daemon=True).start()
    threading.Thread(target=udp_sink, daemon=True).start()
    print("sinkhole up on", ip, file=sys.stderr, flush=True)
    tcp_server()
