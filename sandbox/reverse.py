"""The deep-insight report: what the sample IS (static) and what it DID (dynamic), in one structure.

Dynamic analysis parses the strace (or QEMU_STRACE) output and the sinkhole log from one detonation:
  - syscall histogram and a timeline (first 400 events: t+ms, pid, syscall, argument summary, result)
  - process tree (clone/fork/vfork/execve) and signals
  - file activity: opened/created/unlinked/renamed paths, writes to persistence locations, self-deletion
  - network: every connect()/sendto()/bind()/listen(), DNS questions, what the bot sent first (sinkhole heads)
  - C2 ranking: an endpoint dialled again and again (or a name resolved first) vs one-shot scanning
  - capability hints -> MITRE ATT&CK technique ids (deterministic rules, listed with the evidence line)
  - a plain-English verdict and the pcap/strace artefacts the analyst can download

Static analysis is sandbox.triage + sandbox.elf. `report(sha)` merges both into the Reverse tab's payload.
Nothing here needs an LLM; sandbox.explain can add a write-up on top when a key is configured (BYOK).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

from . import config

# strace:   connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16) = 0
# QEMU:     connect(3,{sin_family=AF_INET,sin_port=htons(80),sin_addr=inet_addr("1.2.3.4")},16) = 0
CONNECT_RE = re.compile(r'connect\(\d+,\s*\{[^}]*?sin_port=htons\((\d+)\)[^}]*?sin_addr=inet_addr\("([\d.]+)"\)')
SENDTO_RE = re.compile(r'sendto\(\d+,.{0,400}?sin_port=htons\((\d+)\)[^}]*?sin_addr=inet_addr\("([\d.]+)"\)')
BIND_RE = re.compile(r'bind\(\d+,\s*\{[^}]*?sin_port=htons\((\d+)\)')
LINE_RE = re.compile(r'^(?:(?P<pid>\d+)\s+)?(?:(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+)?(?P<call>[a-z_0-9]+)\((?P<args>.*?)\)\s*=\s*(?P<ret>-?\d+|0x[0-9a-f]+|\?)(?P<err>\s+[A-Z]+\s*\([^)]*\))?')
OPEN_RE = re.compile(r'open(?:at)?\((?:AT_FDCWD|\d+),\s*"([^"]{1,200})"(?:,\s*([A-Z_|]+))?')
UNLINK_RE = re.compile(r'unlink(?:at)?\((?:AT_FDCWD,\s*)?"([^"]{1,200})"')
RENAME_RE = re.compile(r'rename(?:at2?)?\((?:AT_FDCWD,\s*)?"([^"]{1,200})",\s*(?:AT_FDCWD,\s*)?"([^"]{1,200})"')
EXEC_RE = re.compile(r'execve\("([^"]{1,200})",\s*\[([^\]]{0,400})\]')
WRITE_RE = re.compile(r'write\((\d+),\s*"((?:[^"\\]|\\.){0,160})')
KILL_RE = re.compile(r'kill\((-?\d+),\s*(SIG[A-Z0-9]+|\d+)\)')
SIGNAL_RE = re.compile(r'--- (SIG[A-Z0-9]+)')
PRCTL_RE = re.compile(r'prctl\(PR_SET_NAME,\s*"([^"]{0,64})"')
QNAME_RE = re.compile(r'^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,62}[a-z0-9_])?)*$')
SCAN_PORTS = {23, 2323, 80, 8080, 81, 8081, 37215, 52869, 5555, 7547, 49152, 8443, 443, 22, 2222, 5000, 60001, 9000, 8291, 1900, 554, 8000, 8888, 3389, 445, 139, 21, 25, 110, 143, 3306, 6379, 27017, 9200, 5900, 1433, 161, 53}
PERSIST = ("/etc/rc.local", "/etc/init.d", "/etc/rc", "/etc/cron", "/var/spool/cron", "/etc/systemd", "/etc/profile", "/root/.bashrc",
           "/etc/ld.so.preload", "/etc/inittab", "/etc/xinetd", "authorized_keys", "/etc/passwd", "/etc/shadow")
DEFENCE = ("/dev/watchdog", "/dev/misc/watchdog", "/proc/sys/kernel", "iptables", "/etc/hosts.deny", "/dev/kmsg")
RECON = ("/proc/cpuinfo", "/proc/meminfo", "/proc/net/route", "/proc/net/tcp", "/proc/mounts", "/proc/self/exe", "/etc/os-release",
         "/proc/version", "/sys/class/net", "/proc/net/arp", "/proc/net/dev")
NOISE_IPS = {"8.8.8.8", "1.1.1.1", "0.0.0.0", "255.255.255.255", "8.8.4.4", "9.9.9.9"}


def _parse_ts(ts: str) -> float:
    h, m, s = ts.split(":")
    return int(h) * 3600 + int(m) * 60 + float(s)


def analyse_dynamic(outdir: str, sink_ip: str) -> Dict[str, Any]:
    res: Dict[str, Any] = {"connects": [], "dns": [], "ports": {}, "syscalls": {}, "files": {"opened": [], "created": [], "unlinked": [], "renamed": [], "persistence": [], "defence": [], "recon": []},
                           "procs": {"forks": 0, "execs": [], "names": [], "kills": [], "signals": []}, "sinkhole_hits": [], "udp_payloads": [],
                           "binds": [], "writes_sample": [], "timeline": [], "errors": {}}
    try:
        st = open(os.path.join(outdir, "strace.txt"), errors="ignore").read()
    except FileNotFoundError:
        st = ""
    attempts: Dict[tuple, int] = {}
    t0 = None
    self_deleted = False
    exe_paths = {"/tmp/x"}
    for line in st.splitlines():
        m = LINE_RE.match(line)
        if m:
            call = m.group("call")
            res["syscalls"][call] = res["syscalls"].get(call, 0) + 1
            if m.group("err"):
                e = m.group("err").strip().split()[0]
                res["errors"][e] = res["errors"].get(e, 0) + 1
            if len(res["timeline"]) < 400:
                rel = None
                if m.group("ts"):
                    t = _parse_ts(m.group("ts"))
                    t0 = t if t0 is None else t0
                    rel = round((t - t0) * 1000)
                res["timeline"].append({"t_ms": rel, "pid": m.group("pid"), "call": call, "args": m.group("args")[:140], "ret": (m.group("ret") + (m.group("err") or "")).strip()[:40]})
        if "clone(" in line or "fork(" in line or "vfork(" in line or "clone3(" in line:
            res["procs"]["forks"] += 1
        em = EXEC_RE.search(line)
        if em and len(res["procs"]["execs"]) < 40:
            res["procs"]["execs"].append({"path": em.group(1), "argv": em.group(2)[:300]})
        pm = PRCTL_RE.search(line)
        if pm:
            nm = pm.group(1).replace("\\0", "").replace("\\x00", "").strip()
            if nm and nm not in res["procs"]["names"]:
                res["procs"]["names"].append(nm)
        km = KILL_RE.search(line)
        if km and len(res["procs"]["kills"]) < 40:
            res["procs"]["kills"].append({"pid": km.group(1), "sig": km.group(2)})
        sm = SIGNAL_RE.search(line)
        if sm and len(res["procs"]["signals"]) < 40:
            res["procs"]["signals"].append(sm.group(1))
        om = OPEN_RE.search(line)
        if om:
            p, flags = om.group(1), om.group(2) or ""
            f = res["files"]
            if p not in f["opened"] and len(f["opened"]) < 200:
                f["opened"].append(p)
            if "O_CREAT" in flags and p not in f["created"] and len(f["created"]) < 60:
                f["created"].append(p)
            if any(p.startswith(k) or k in p for k in PERSIST) and p not in f["persistence"]:
                f["persistence"].append(p)
            if any(k in p for k in DEFENCE) and p not in f["defence"]:
                f["defence"].append(p)
            if any(p.startswith(k) for k in RECON) and p not in f["recon"]:
                f["recon"].append(p)
        um = UNLINK_RE.search(line)
        if um:
            p = um.group(1)
            if p not in res["files"]["unlinked"] and len(res["files"]["unlinked"]) < 60:
                res["files"]["unlinked"].append(p)
            if p in exe_paths or p.endswith("/x"):
                self_deleted = True
        rm = RENAME_RE.search(line)
        if rm and len(res["files"]["renamed"]) < 30:
            res["files"]["renamed"].append([rm.group(1), rm.group(2)])
        bm = BIND_RE.search(line)
        if bm and len(res["binds"]) < 20:
            res["binds"].append(int(bm.group(1)))
        for mm in CONNECT_RE.finditer(line):
            port, ip = int(mm.group(1)), mm.group(2)
            if not ip.startswith("127."):
                attempts[(ip, port, False)] = attempts.get((ip, port, False), 0) + 1
        for mm in SENDTO_RE.finditer(line):
            port, ip = int(mm.group(1)), mm.group(2)
            if port != 53 and not ip.startswith("127."):
                attempts[(ip, port, True)] = attempts.get((ip, port, True), 0) + 1
        wm = WRITE_RE.search(line)
        if wm and wm.group(1) not in ("1", "2") and len(res["writes_sample"]) < 30:
            res["writes_sample"].append({"fd": wm.group(1), "data": wm.group(2)[:160]})
    for (ip, port, udp), n in sorted(attempts.items(), key=lambda kv: -kv[1])[:400]:
        res["connects"].append({"ip": ip, "port": port, "udp": udp, "attempts": n, "via_sinkhole": ip == sink_ip})
    res["connect_attempts"] = sum(attempts.values())
    res["distinct_targets"] = len(attempts)
    res["self_deleted"] = self_deleted
    # ── sinkhole: what actually arrived, with the ORIGINAL destination, plus the first bytes ─────────────────
    try:
        for ln in open(os.path.join(outdir, "sinkhole.jsonl"), errors="ignore"):
            try:
                e = json.loads(ln)
            except ValueError:
                continue
            if e.get("kind") == "dns" and e.get("qname"):
                q = e["qname"].strip(".").lower()
                if QNAME_RE.match(q):
                    if q not in res["dns"] and len(res["dns"]) < 40:
                        res["dns"].append(q)
                else:
                    res["dns_malformed"] = res.get("dns_malformed", 0) + 1
            if e.get("kind") == "tcp":
                res["ports"][str(e.get("dport"))] = res["ports"].get(str(e.get("dport")), 0) + 1
                if len(res["sinkhole_hits"]) < 60:
                    res["sinkhole_hits"].append({"dst": e.get("dst"), "dport": e.get("dport"), "bytes": e.get("bytes"), "head": (e.get("head_text") or "")[:200],
                                                 "head_hex": (e.get("head_hex") or "")[:96], "after_banner": (e.get("after_banner") or "")[:120], "ts": e.get("ts")})
            if e.get("kind") == "udp" and len(res["udp_payloads"]) < 20:
                res["udp_payloads"].append({"bytes": e.get("bytes"), "head": (e.get("head_text") or "")[:120]})
    except FileNotFoundError:
        pass
    # ── the C2 picture ──────────────────────────────────────────────────────────────────────────────────────
    tally: Dict[tuple, int] = {}
    spoke: Dict[tuple, int] = {}      # bytes the sample actually sent to that endpoint (a beacon speaks first; a scanner mostly does not)
    for c in res["connects"]:
        if not c["via_sinkhole"] and c["ip"] not in NOISE_IPS:
            tally[(c["ip"], c["port"])] = tally.get((c["ip"], c["port"]), 0) + c["attempts"]
    for h in res["sinkhole_hits"]:
        if h.get("dst") and h["dst"] not in (sink_ip, "?"):
            k = (h["dst"], h["dport"])
            tally[k] = tally.get(k, 0) + 1
            spoke[k] = spoke.get(k, 0) + int(h.get("bytes") or 0)
    ranked = sorted(tally.items(), key=lambda kv: (-kv[1], -spoke.get(kv[0], 0)))
    total = sum(n for _, n in ranked) or 1
    # a C2 is dialled again and again (>= 5 or >= 20 % of all dials), OR it is the endpoint the sample SPOKE to on a
    # port that is not a scan port (a beacon: "7HdAFTuVf unknown.iot" to :2139 once in 60 s is the C2, the 24 silent
    # telnet dials are the scan). Foreign-arch runs rely on this: QEMU's tracer does not decode sockaddrs.
    res["c2_likely"] = [{"endpoint": f"{ip}:{port}", "attempts": n, "share": round(n / total, 3), "spoke_bytes": spoke.get((ip, port), 0),
                         "why": "repeat dials" if (n >= 5 or n / total >= 0.2) else "beacon payload on a non-scan port"}
                        for (ip, port), n in ranked
                        if n >= 5 or n / total >= 0.2 or (spoke.get((ip, port), 0) > 0 and port not in SCAN_PORTS)][:10]
    res["scan_targets"] = sum(1 for (ip, port), n in ranked if n == 1 and port in SCAN_PORTS)
    res["scan_ports"] = sorted({port for (ip, port), n in ranked if port in SCAN_PORTS})[:16]
    res["top_targets"] = [{"endpoint": f"{ip}:{port}", "attempts": n} for (ip, port), n in ranked[:25]]
    res["c2_candidates"] = [c["endpoint"] for c in res["c2_likely"]] or [f"{ip}:{port}" for (ip, port), n in ranked[:5]]
    res["c2_extracted"] = bool(res["c2_likely"] or res["dns"])
    # protocol guess from the first bytes the bot sent to its C2
    proto = None
    for h in res["sinkhole_hits"]:
        head = h.get("head") or ""
        if head.startswith(("GET ", "POST ", "HEAD ")):
            proto = "HTTP"
        elif head.upper().startswith(("NICK", "USER", "PASS ")):
            proto = "IRC"
        elif h.get("dport") in (23, 2323):
            proto = "telnet"
        elif head and h["dport"] not in SCAN_PORTS:
            proto = proto or "custom binary"
        if proto:
            break
    res["c2_protocol"] = proto
    res["attack"] = attack_hints(res)
    res["verdict"] = verdict(res)
    return res


def attack_hints(res: Dict[str, Any]) -> List[Dict[str, str]]:
    """Deterministic ATT&CK technique hints with the evidence that fired them."""
    out: List[Dict[str, str]] = []
    f = res.get("files", {})
    def add(tid, name, ev):
        out.append({"technique": tid, "name": name, "evidence": str(ev)[:200]})
    if res.get("c2_likely"):
        add("T1071" if res.get("c2_protocol") in ("HTTP", "IRC") else "T1095", "Application layer / non-application layer C2 protocol",
            f"{res['c2_likely'][0]['endpoint']} dialled {res['c2_likely'][0]['attempts']}× ({res.get('c2_protocol') or 'protocol unknown'})")
    if res.get("dns"):
        add("T1568", "Dynamic resolution", f"resolved {', '.join(res['dns'][:3])}")
    if res.get("scan_targets", 0) >= 10:
        add("T1046", "Network service discovery (scanning)", f"{res['scan_targets']} one-shot targets on ports {res.get('scan_ports')}")
    if any(p in (23, 2323) for p in res.get("scan_ports", [])) and res.get("scan_targets", 0) >= 5:
        add("T1110", "Brute force (telnet)", "telnet ports scanned at volume")
    if f.get("persistence"):
        add("T1037/T1053", "Boot or logon initialization scripts / scheduled task", ", ".join(f["persistence"][:4]))
    if res.get("self_deleted"):
        add("T1070.004", "Indicator removal: file deletion (self-delete)", "the running binary unlinked itself")
    if f.get("defence"):
        add("T1562", "Impair defences", ", ".join(f["defence"][:4]))
    if res.get("procs", {}).get("kills"):
        add("T1489", "Service stop / process kill", f"{len(res['procs']['kills'])} kill() calls")
    if res.get("procs", {}).get("names"):
        add("T1036", "Masquerading (process rename)", ", ".join(res["procs"]["names"][:4]))
    if f.get("recon"):
        add("T1082", "System information discovery", ", ".join(f["recon"][:4]))
    if any(e["path"] in ("/bin/sh", "/bin/busybox", "/bin/bash") or "wget" in e.get("argv", "") or "curl" in e.get("argv", "") or "tftp" in e.get("argv", "") for e in res.get("procs", {}).get("execs", [])):
        add("T1105", "Ingress tool transfer (downloader)", res["procs"]["execs"][0]["argv"][:120])
    if res.get("binds"):
        add("T1571", "Non-standard port / listener", f"bind() on {res['binds'][:5]}")
    if res.get("procs", {}).get("forks", 0) >= 20:
        add("T1498", "Network denial of service (flooder worker pool)", f"{res['procs']['forks']} forks")
    return out


def verdict(res: Dict[str, Any]) -> str:
    if res.get("c2_extracted"):
        tgt = res["dns"][:3] or [c["endpoint"] for c in res["c2_likely"][:3]]
        base = "C2 " + ", ".join(tgt)
        if res.get("c2_protocol"):
            base += f" over {res['c2_protocol']}"
        if res.get("scan_targets"):
            base += f"; also scanning {res['scan_targets']} targets"
        return base
    if res.get("scan_targets"):
        return f"scanner only: {res['scan_targets']} targets on ports {res['scan_ports']}"
    if res.get("connect_attempts"):
        return f"{res['connect_attempts']} connection attempts, no repeat endpoint"
    if res.get("files", {}).get("persistence"):
        return "no network; wrote persistence: " + ", ".join(res["files"]["persistence"][:2])
    return "no network behaviour observed in the window"


def report(sha: str) -> Dict[str, Any]:
    """Static + dynamic in one payload for the Reverse tab."""
    from . import cell, triage
    out: Dict[str, Any] = {"sha256": sha}
    try:
        with open(os.path.join(config.SAMPLES, sha + ".json"), encoding="utf-8") as f:
            out["static"] = json.load(f)
    except (OSError, ValueError):
        out["static"] = None
    out["dynamic"] = cell.load_detonation(sha)
    p = os.path.join(config.SAMPLES, sha)
    if os.path.isfile(p):
        out["hexdump"] = triage.hexdump(p, 512)
    out["artifacts"] = {k: os.path.exists(os.path.join(config.DETONATIONS, f"{sha}.{k}")) for k in ("strace.txt", "sinkhole.jsonl", "pcap", "stdout.txt")}
    out["summary"] = summary_lines(out)
    return out


def summary_lines(rep: Dict[str, Any]) -> List[str]:
    """The deterministic write-up (what the UI shows when no BYOK key is set)."""
    s, d = rep.get("static") or {}, rep.get("dynamic") or {}
    lines: List[str] = []
    if s:
        lines.append(f"Sample {s['sha256'][:16]}… is {s.get('static_verdict') or s.get('kind')} ({s.get('size')} bytes, entropy {s.get('entropy')}).")
        e = s.get("elf") or {}
        if e.get("needed"):
            lines.append("Links against " + ", ".join(e["needed"][:6]) + ".")
        if e.get("imports"):
            net = [i for i in e["imports"] if i in ("socket", "connect", "send", "sendto", "recv", "getaddrinfo", "gethostbyname", "bind", "listen", "accept")]
            if net:
                lines.append("Imports network calls: " + ", ".join(net) + ".")
        if s.get("credentials", {}).get("default_credentials_seen", 0) >= 6:
            lines.append(f"Carries a default-credential table ({s['credentials']['default_credentials_seen']} classic IoT logins): telnet brute-force capability.")
        io = s.get("iocs", {})
        if io.get("urls") or io.get("ip_ports"):
            lines.append("Hard-coded indicators: " + ", ".join((io.get("urls") or [])[:3] + (io.get("ip_ports") or [])[:3]) + ".")
    if d and d.get("run", {}).get("status") == "ran":
        lines.append(f"Detonated for {d.get('timeout_s')} s ({d['run'].get('tracer')}): {d.get('verdict')}.")
        if d.get("procs", {}).get("forks"):
            lines.append(f"Spawned {d['procs']['forks']} child processes" + (f", renamed itself to {d['procs']['names'][0]!r}" if d["procs"].get("names") else "") + ".")
        if d.get("files", {}).get("persistence"):
            lines.append("Touched persistence paths: " + ", ".join(d["files"]["persistence"][:3]) + ".")
        if d.get("self_deleted"):
            lines.append("Deleted its own binary after start (anti-forensics).")
        if d.get("sinkhole_hits"):
            h = d["sinkhole_hits"][0]
            lines.append(f"First bytes to {h.get('dst')}:{h.get('dport')}: {h.get('head')[:80]!r}.")
        if d.get("attack"):
            lines.append("ATT&CK: " + "; ".join(f"{a['technique']} {a['name']}" for a in d["attack"][:6]) + ".")
    elif d:
        lines.append(f"Detonation status: {d.get('run', {}).get('status')} {d.get('run', {}).get('hint') or d.get('run', {}).get('note') or ''}".strip())
    else:
        lines.append("Not detonated yet.")
    return lines
