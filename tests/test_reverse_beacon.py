"""Foreign-arch style detonation: the tracer decodes nothing, the sinkhole sees 24 silent telnet dials and one
payload to a non-scan port. The payload endpoint must be the C2; a malformed DNS name must not become the verdict."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def test_beacon_on_non_scan_port_is_c2_and_junk_dns_is_dropped(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_DATA", str(tmp_path / "d"))
    for m in [m for m in list(sys.modules) if m.startswith("sandbox")]:
        del sys.modules[m]
    from sandbox import reverse
    out = tmp_path / "out"
    out.mkdir()
    (out / "strace.txt").write_text("22 connect(3,0x40800720,16) = 0\n" * 25)       # undecoded sockaddrs
    hits = [{"kind": "dns", "qname": ",0x40800720,0x4080071c)", "answered": "10.66.0.2"},
            {"kind": "dns", "qname": "cnc.example.net.", "answered": "10.66.0.2"},
            {"kind": "tcp", "src": "10.66.0.3", "dst": "176.65.139.131", "dport": 2139, "bytes": 60, "head_text": "7HdAFTuVf unknown.iot ", "ts": "t"}]
    hits += [{"kind": "tcp", "src": "10.66.0.3", "dst": f"141.96.{i}.90", "dport": 23, "bytes": 0, "head_text": "", "ts": "t"} for i in range(24)]
    (out / "sinkhole.jsonl").write_text("\n".join(json.dumps(h) for h in hits) + "\n")
    r = reverse.analyse_dynamic(str(out), "10.66.0.2")
    assert r["dns"] == ["cnc.example.net"] and r["dns_malformed"] == 1
    assert r["c2_likely"] and r["c2_likely"][0]["endpoint"] == "176.65.139.131:2139" and r["c2_likely"][0]["why"].startswith("beacon")
    assert r["scan_targets"] == 24 and r["scan_ports"] == [23]
    assert r["verdict"].startswith("C2 cnc.example.net") and "scanning 24" in r["verdict"]
    assert {"T1095", "T1046", "T1110", "T1568"} <= {a["technique"] for a in r["attack"]}
