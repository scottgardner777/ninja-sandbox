"""Static triage: everything we can say about a sample WITHOUT running it.

Lifted from the skunkbox honeynet's samples/triage.py (kind + arch + URLs/IPs) and extended for the Reverse tab:
strings (ASCII + UTF-16LE), IOCs (URLs, IPs, domains, e-mails, onion addresses, wallet-looking strings),
file entropy and packer hints, embedded shell commands, credential lists (Mirai-style user:pass tables),
and the ELF structure from sandbox.elf. Deterministic; no network; a few ms per sample.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import time
from typing import Any, Dict, List

from . import elf as elfmod

ARCH = {3: "x86", 62: "x86-64", 40: "arm", 183: "aarch64", 8: "mips", 20: "ppc", 21: "ppc64", 42: "sh4", 2: "sparc",
        43: "sparc64", 4: "m68k", 243: "riscv"}
URL_RE = re.compile(rb"(?:https?|ftp|tftp)://[^\s'\"<>`;|\x00]{4,200}")
IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IPPORT_RE = re.compile(rb"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b")
DOMAIN_RE = re.compile(rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|cc|info|biz|su|tk|ml|ga|cf|gq|pw|me|to|onion|dev|app|site|online|club|shop|link|ws|in|co|uk|de|nl|fr|br|us|eu)\b", re.I)
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
ONION_RE = re.compile(rb"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b")
BTC_RE = re.compile(rb"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
XMR_RE = re.compile(rb"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
SHELL_RE = re.compile(rb"(?:wget|curl|tftp|busybox|chmod\s+[0-7x+]+|/bin/sh|/bin/bash|nohup|crontab|iptables|killall|pkill|rm\s+-rf|cd\s+/tmp|cd\s+/var/run|echo\s+-e)[^\n\x00]{0,160}")
CRED_RE = re.compile(rb"\b(root|admin|user|guest|support|service|supervisor|ubnt|default|telnet|pi|vizxv|xc3511|juantech|888888|666666|klv123|realtek|000000|1234|12345|123456|password|pass|admin1234|smcadmin|hi3518|jvbzd|anko|zlxx\.|7ujMko0|dreambox)\b")
PRIVATE_IP_PREFIX = (b"0.", b"127.", b"10.", b"192.168.", b"255.", b"169.254.", b"224.", b"239.", b"172.16.", b"172.17.", b"172.18.", b"172.19.", b"172.2", b"172.30.", b"172.31.")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

INTERESTING = ("/proc/", "/dev/watchdog", "/dev/misc/watchdog", "/etc/rc.local", "/etc/init.d", "/etc/cron", "/var/spool/cron",
               "authorized_keys", "/etc/passwd", "/etc/shadow", "LD_PRELOAD", "/tmp/", "/var/run/", "/dev/shm", "ptrace",
               "iptables", "setsid", "fork", "daemon", "mining", "stratum", "xmrig", "pool", "ddos", "flood", "syn", "udp",
               "attack", "bot", "irc", "PRIVMSG", "NICK", "JOIN", "USER", "GET /", "POST /", "User-Agent", "Mozilla",
               "x86_64", "mips", "arm", "sh4", "busybox", "ELF", "/bin/busybox", "ENABLE", "SYSTEM", "cat /proc/mounts")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def kind_of(b: bytes):
    if b[:4] == b"\x7fELF":
        little = b[5] == 1
        m = struct.unpack("<H" if little else ">H", b[18:20])[0]
        return "elf", {"bits": 32 if b[4] == 1 else 64, "arch": ARCH.get(m, str(m)), "endian": "le" if little else "be"}
    if b[:2] == b"MZ":
        return "pe", {"note": "Windows PE: static triage only, the cell runs Linux ELF"}
    if b[:4] == b"%PDF":
        return "pdf", {}
    if b[:2] == b"PK":
        return "zip", {"note": "zip/jar/apk/docx container: static triage only"}
    if b.startswith(b"ssh-rsa ") or b.startswith(b"ssh-ed25519 ") or b.startswith(b"ecdsa-sha2-"):
        parts = b.split()
        return "sshkey", {"key_type": parts[0].decode("latin1"), "comment": (parts[2].decode("latin1", "replace")[:60] if len(parts) > 2 else "")}
    if b[:2] == b"#!" or re.match(rb"^\s*(cd|sh|rm|wget|curl|busybox|/bin/busybox|tftp|ftpget|chmod|echo|export)\b", b[:60]):
        return "script", {}
    printable = sum(1 for c in b[:512] if 32 <= c < 127 or c in (9, 10, 13))
    if printable > 0.9 * max(1, len(b[:512])):
        return "text", {}
    return "other", {"magic": b[:8].hex()}


def strings(b: bytes, min_len: int = 5, limit: int = 3000) -> Dict[str, List[str]]:
    """ASCII and UTF-16LE strings, deduplicated, order preserved, bounded."""
    asc = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, b)
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, b)
    seen = set()
    out_a: List[str] = []
    for s in asc:
        t = s.decode("ascii")
        if t not in seen:
            seen.add(t)
            out_a.append(t[:300])
            if len(out_a) >= limit:
                break
    out_w: List[str] = []
    for s in wide:
        t = s.decode("utf-16le", "replace")
        if t not in seen:
            seen.add(t)
            out_w.append(t[:300])
            if len(out_w) >= 500:
                break
    return {"ascii": out_a, "utf16": out_w, "n_ascii_total": len(asc), "n_utf16_total": len(wide)}


def iocs(b: bytes) -> Dict[str, Any]:
    urls = sorted({u.decode("latin1", "replace")[:200] for u in URL_RE.findall(b)})[:40]
    ips = sorted({i.decode("latin1") for i in IP_RE.findall(b) if not i.startswith(PRIVATE_IP_PREFIX)})[:60]
    ipports = sorted({f"{i.decode()}:{p.decode()}" for i, p in IPPORT_RE.findall(b) if not i.startswith(PRIVATE_IP_PREFIX)})[:40]
    doms = sorted({d.decode("latin1", "replace").lower() for d in DOMAIN_RE.findall(b)
                   if not re.search(rb"\.(so|c|h|cpp|txt|conf|py|sh|o|a|ko|elf)$", d, re.I)})[:40]
    return {"urls": urls, "ips": ips, "ip_ports": ipports, "domains": doms,
            "emails": sorted({e.decode("latin1", "replace") for e in EMAIL_RE.findall(b)})[:10],
            "onions": sorted({o.decode("latin1") for o in ONION_RE.findall(b)})[:10],
            "wallets": {"btc": sorted({w.decode("latin1") for w in BTC_RE.findall(b)})[:5],
                        "xmr": sorted({w.decode("latin1") for w in XMR_RE.findall(b)})[:5]},
            "shell_commands": sorted({s.decode("latin1", "replace")[:200] for s in SHELL_RE.findall(b)})[:40]}


def credential_hints(b: bytes) -> Dict[str, Any]:
    """Mirai-family bots carry a telnet credential table; count distinct hits of the classic defaults."""
    hits = {}
    for m in CRED_RE.finditer(b):
        w = m.group(1).decode("latin1")
        hits[w] = hits.get(w, 0) + 1
    return {"default_credentials_seen": len(hits), "words": sorted(hits, key=lambda k: -hits[k])[:30]}


def interesting_strings(strs: List[str]) -> List[str]:
    out = []
    for s in strs:
        low = s.lower()
        if any(k.lower() in low for k in INTERESTING):
            out.append(s)
            if len(out) >= 120:
                break
    return out


def triage_bytes(b: bytes, size: int, first_seen: float) -> Dict[str, Any]:
    kind, meta = kind_of(b)
    rec: Dict[str, Any] = {"sha256": hashlib.sha256(b).hexdigest(), "md5": hashlib.md5(b).hexdigest(), "sha1": hashlib.sha1(b).hexdigest(),
                           "size": size, "first_seen": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(first_seen)),
                           "kind": kind, "triaged": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                           "entropy": elfmod.entropy(b[:1 << 22])}
    rec.update(meta)
    rec["iocs"] = iocs(b)
    st = strings(b)
    rec["strings_count"] = {"ascii": st["n_ascii_total"], "utf16": st["n_utf16_total"]}
    rec["interesting_strings"] = interesting_strings(st["ascii"] + st["utf16"])
    rec["credentials"] = credential_hints(b)
    if kind == "elf":
        rec["elf"] = elfmod.parse(b)
        rec["packer"] = rec["elf"].get("packer")
    else:
        rec["packer"] = "UPX" if b.find(b"UPX!") != -1 else None
    if kind in ("script", "text"):
        rec["head"] = b[:1200].decode("latin1", "replace")
    rec["high_entropy"] = rec["entropy"] >= 7.2
    # a one-line static verdict for the list view
    bits = []
    if kind == "elf":
        bits.append(rec["elf"].get("summary", "ELF"))
    else:
        bits.append(kind)
    if rec["packer"]:
        bits.append(f"packed {rec['packer']}")
    elif rec["high_entropy"]:
        bits.append("high entropy (packed/encrypted?)")
    if rec["credentials"]["default_credentials_seen"] >= 6:
        bits.append(f"{rec['credentials']['default_credentials_seen']} default-credential words (telnet brute table)")
    if rec["iocs"]["urls"]:
        bits.append(f"{len(rec['iocs']['urls'])} URLs")
    if rec["iocs"]["ip_ports"]:
        bits.append(f"{len(rec['iocs']['ip_ports'])} ip:port")
    rec["static_verdict"] = "; ".join(bits)
    return rec


def triage_file(path: str, origin: str = "upload", name: str = "") -> Dict[str, Any]:
    st = os.stat(path)
    with open(path, "rb") as f:
        b = f.read(64 * 1024 * 1024)
    rec = triage_bytes(b, st.st_size, st.st_mtime)
    rec["origin"] = origin
    rec["name"] = (name or os.path.basename(path))[:120]
    return rec


def full_strings(path: str) -> Dict[str, List[str]]:
    with open(path, "rb") as f:
        return strings(f.read(64 * 1024 * 1024), limit=8000)


def hexdump(path: str, length: int = 512, offset: int = 0) -> str:
    with open(path, "rb") as f:
        f.seek(offset)
        b = f.read(length)
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        hx = " ".join(f"{c:02x}" for c in chunk)
        tx = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"{offset + i:08x}  {hx:<48}  {tx}")
    return "\n".join(lines)


def save_record(samples_dir: str, rec: Dict[str, Any]) -> str:
    p = os.path.join(samples_dir, rec["sha256"] + ".json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=1)
    return p
