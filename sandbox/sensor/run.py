"""The sensor loop: lines in -> aggregates + DNA + droppers + samples out, every few seconds.

    python -m sandbox.sensor.run            (the `sensor` service in docker-compose)

State on disk (sandbox.config.SENSOR):
  sensor.json      the current picture the UI's Sensor tab reads: window stats, top IPs, probe families, DNA summary
  requests.jsonl   the bounded request stream (last `retain_requests`), DNA input; owner/private IPs already dropped
  droppers.jsonl   every dropper URL seen at the edge (append-only)
  state.json       tail offsets + telemetry cursor

"Load the malware in situ": a dropper URL seen in attack traffic becomes a sample when settings.cell.fetch_droppers
is on (fetched by a throwaway container with a size cap, never on the host). Watch dirs (honeypot download folders,
quarantine) are ingested as samples too. Both can auto-detonate (settings.cell.auto_detonate).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from typing import Dict, List

from .. import config, dna
from . import core, inputs, parsers

STATE_F = os.path.join(config.SENSOR, "state.json")
PICTURE_F = os.path.join(config.SENSOR, "sensor.json")
REQ_F = os.path.join(config.SENSOR, "requests.jsonl")
DROP_F = os.path.join(config.SENSOR, "droppers.jsonl")
TICK_S = float(os.environ.get("SENSOR_TICK_S", "5"))
PICTURE_EVERY_S = float(os.environ.get("SENSOR_PICTURE_EVERY_S", "30"))
TELEMETRY_EVERY_S = float(os.environ.get("SENSOR_TELEMETRY_EVERY_S", "900"))
_lock = threading.Lock()


def load_state() -> dict:
    try:
        return json.load(open(STATE_F, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(st: dict) -> None:
    tmp = STATE_F + ".tmp"
    json.dump(st, open(tmp, "w", encoding="utf-8"))
    os.replace(tmp, STATE_F)


def load_requests(limit: int = 200000) -> List[dict]:
    out: List[dict] = []
    try:
        with open(REQ_F, encoding="utf-8") as f:
            for ln in f:
                try:
                    out.append(json.loads(ln))
                except ValueError:
                    pass
    except OSError:
        pass
    return out[-limit:]


def trim_requests(keep: int) -> None:
    rows = load_requests(keep)
    tmp = REQ_F + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, REQ_F)


def build_picture(agg_rows: List[dict], window_h: int, settings: dict, dna_min: int = 3) -> dict:
    reqs = load_requests(int(settings["sensor"].get("retain_requests", 200000)))
    since = time.time() - window_h * 3600
    recent = [r for r in reqs if float(r.get("ts") or 0) >= since]
    d = dna.analyse(recent, min_requests=dna_min, exclude=settings["sensor"].get("exclude") or [])
    # fold the per-IP rows into a top list
    rows = sorted(agg_rows, key=lambda r: -r["req"])
    fam_counts: Dict[str, int] = {}
    cves: Dict[str, int] = {}
    for r in agg_rows:
        for p in r["probes"].values():
            fam_counts[p["family"]] = fam_counts.get(p["family"], 0) + p["count"]
            if p.get("cve"):
                cves[p["cve"]] = cves.get(p["cve"], 0) + p["count"]
    top = []
    for r in rows[:60]:
        prof = d["profiles"].get(r["ip"]) or {}
        top.append({"ip": r["ip"], "req": r["req"], "cc": r.get("cc"), "first": r["first"], "last": r["last"],
                    "sites": sorted(r["sites"], key=lambda h: -r["sites"][h]["req"])[:5],
                    "families": sorted({p["family"] for p in r["probes"].values()}),
                    "cves": sorted({p["cve"] for p in r["probes"].values() if p.get("cve")}),
                    "ua": max(r["ua"], key=r["ua"].get) if r["ua"] else "", "status": r["status"], "droppers": r.get("droppers", []),
                    "archetype": (prof.get("archetype") or {}).get("primary"), "confidence": (prof.get("archetype") or {}).get("confidence"),
                    "dna_hash": prof.get("dna_hash"), "kill_chain": list((prof.get("kill_chain") or {}).keys()),
                    "next": ((prof.get("markov") or {}).get("predictions") or [None])[0]})
    droppers = []
    try:
        with open(DROP_F, encoding="utf-8") as f:
            for ln in f.readlines()[-200:]:
                try:
                    droppers.append(json.loads(ln))
                except ValueError:
                    pass
    except OSError:
        pass
    return {"as_of": config.now_iso(), "window_h": window_h, "requests_in_window": len(recent), "ips": len(agg_rows),
            "probing_ips": sum(1 for r in agg_rows if r["probes"]), "families": dict(sorted(fam_counts.items(), key=lambda kv: -kv[1])),
            "cves": dict(sorted(cves.items(), key=lambda kv: -kv[1])), "top": top,
            "dna": {"summary": d["summary"], "clusters": d["clusters"][:20], "narratives": d["narratives"][:25]},
            "droppers": droppers[::-1][:100], "input": settings["sensor"].get("input"), "format": settings["sensor"].get("format")}


def telemetry_payload(agg_rows: List[dict], settings: dict, samples_summary: List[dict]) -> dict:
    """EXACTLY what leaves the box when telemetry is on. The Settings tab renders this same function's output."""
    return {"v": 1, "install_id": settings["telemetry"]["install_id"], "mode": settings["mode"], "sent_at": config.now_iso(),
            "sensor": {"rows": [{k: v for k, v in r.items() if k != "droppers"} | {"droppers": len(r.get("droppers") or [])} for r in agg_rows[:5000]],
                       "note": "per-IP aggregates only: counts, status classes, probe families, UA family, country. No URIs beyond the bounded probe pattern, no headers, no bodies."},
            "samples": [{"sha256": s.get("sha256"), "kind": s.get("kind"), "arch": s.get("arch"), "size": s.get("size"), "verdict": s.get("verdict"),
                         "c2": s.get("c2_candidates"), "origin": (s.get("origin") or "").split(":")[0]} for s in samples_summary[:200]],
            "share_samples": bool(settings["telemetry"].get("share_samples"))}


class Sensor:
    def __init__(self):
        config.ensure_dirs()
        self.settings = config.load_settings()
        self.state = load_state()
        self.owner = core.load_nets(self.settings["sensor"].get("exclude") or [])
        self.agg = core.Agg()
        self.agg_window_start = time.time()
        self.unparsed = 0
        self.reqf = open(REQ_F, "a", encoding="utf-8")
        self.dropf = open(DROP_F, "a", encoding="utf-8")
        self.last_picture = 0.0
        self.last_telemetry = float(self.state.get("last_telemetry") or 0)
        self.last_watch = 0.0
        self.seen_droppers = set(self.state.get("seen_droppers") or [])
        self.fmt = self.settings["sensor"].get("format", "auto")

    # ── ingest ─────────────────────────────────────────────────────────────────────────────────────────
    def on_line(self, line: str, source: str) -> None:
        r = parsers.parse(line, self.fmt)
        if not r:
            self.unparsed += 1
            return
        with _lock:
            row = self.agg.add(r, self.owner)
            if row is None:
                return
            flat = {"ts": r["ts"], "ip": r["ip"], "host": r["host"], "path": r["path"], "uri": r["uri"][:400], "method": r["method"],
                    "status": r["status"], "size": r["size"], "user_agent": r["user_agent"][:200], "cc": r.get("cc", "")}
            self.reqf.write(json.dumps(flat, ensure_ascii=False) + "\n")
            new_drops = [d for d in self.agg.droppers if d["url"] not in self.seen_droppers]
            for d in new_drops:
                self.seen_droppers.add(d["url"])
                d["source"] = source
                self.dropf.write(json.dumps(d, ensure_ascii=False) + "\n")
                config.event("dropper_seen", ip=d["ip"], url=d["url"], family=d.get("family"), cve=d.get("cve"))
            self.agg.droppers = []
            if new_drops and self.settings["cell"].get("fetch_droppers"):
                for d in new_drops:
                    threading.Thread(target=fetch_dropper, args=(d, self.settings), daemon=True).start()

    # ── watch dirs: honeypot downloads / quarantine folders -> samples ──────────────────────────────────
    def scan_watch_dirs(self) -> None:
        seen = self.state.setdefault("watched", {})
        for d in self.settings["sensor"].get("watch_dirs") or []:
            try:
                names = os.listdir(d)
            except OSError:
                continue
            for n in names:
                p = os.path.join(d, n)
                try:
                    if not os.path.isfile(p) or os.path.getsize(p) <= 1 or os.path.getsize(p) > config.MAX_SAMPLE_BYTES:
                        continue
                    key = f"{d}/{n}:{os.path.getmtime(p)}"
                    if key in seen:
                        continue
                    seen[key] = 1
                    ingest_file(p, origin=f"watch:{d}", settings=self.settings, name=n)
                except OSError:
                    continue

    # ── the picture + telemetry ───────────────────────────────────────────────────────────────────────
    def picture(self) -> None:
        with _lock:
            self.reqf.flush()
            self.dropf.flush()
            rows = self.agg.rows()
        if time.time() - self.agg_window_start > 86400:     # the aggregate window is a rolling day; DNA uses requests.jsonl
            self.agg, self.agg_window_start = core.Agg(), time.time()
        pic = build_picture(rows, 24, self.settings)
        pic["unparsed_lines"] = self.unparsed
        pic["lines_seen"] = self.agg.lines
        tmp = PICTURE_F + ".tmp"
        json.dump(pic, open(tmp, "w", encoding="utf-8"), ensure_ascii=False)
        os.replace(tmp, PICTURE_F)
        if self.agg.lines and self.agg.lines % 50000 == 0:
            trim_requests(int(self.settings["sensor"].get("retain_requests", 200000)))

    def telemetry(self) -> None:
        if not self.settings["telemetry"].get("enabled"):
            return
        with _lock:
            rows = self.agg.rows()
        payload = telemetry_payload(rows, self.settings, samples_summary())
        url = self.settings["telemetry"].get("url") or config.TELEMETRY_URL
        try:
            req = urllib.request.Request(url, json.dumps(payload).encode(), {"Content-Type": "application/json", "User-Agent": "ninja-sandbox-sensor"})
            with urllib.request.urlopen(req, timeout=60) as r:
                res = r.read(300).decode("utf-8", "replace")
            config.event("telemetry_sent", rows=len(payload["sensor"]["rows"]), samples=len(payload["samples"]), response=res[:120])
        except Exception as e:  # noqa: BLE001
            config.event("telemetry_failed", error=f"{type(e).__name__}: {e}"[:200])
        self.last_telemetry = time.time()
        self.state["last_telemetry"] = self.last_telemetry

    def run_forever(self) -> None:
        mode = self.settings["sensor"].get("input", "file")
        tail = None
        if mode == "file":
            paths = self.settings["sensor"].get("log_paths") or []
            tail = inputs.FileTail(paths, self.state)
            print(f"[sensor] tailing {paths or 'nothing (set SENSOR_LOG_PATHS)'}", flush=True)
        elif mode == "syslog":
            inputs.SyslogServer(self.on_line, int(os.environ.get("SENSOR_SYSLOG_PORT", "5514"))).start()
            print("[sensor] syslog listening on :5514 udp+tcp", flush=True)
        elif mode == "inline":
            inputs.InlineProxy(self.on_line, os.environ.get("SENSOR_UPSTREAM", "http://127.0.0.1:3000"), int(os.environ.get("SENSOR_INLINE_PORT", "8080"))).start()
            print("[sensor] inline proxy on :8080 ->", os.environ.get("SENSOR_UPSTREAM"), flush=True)
        self.picture()
        while True:
            try:
                self.settings = config.load_settings()
                self.owner = core.load_nets(self.settings["sensor"].get("exclude") or [])
                self.fmt = self.settings["sensor"].get("format", "auto")
                if tail is not None:
                    tail.paths = self.settings["sensor"].get("log_paths") or []
                    for line, src in tail.read_new():
                        self.on_line(line, src)
                if time.time() - self.last_watch > 20:
                    self.scan_watch_dirs()
                    self.last_watch = time.time()
                if time.time() - self.last_picture > PICTURE_EVERY_S:
                    self.picture()
                    self.last_picture = time.time()
                if time.time() - self.last_telemetry > TELEMETRY_EVERY_S:
                    self.telemetry()
                self.state["seen_droppers"] = sorted(self.seen_droppers)[-5000:]
                save_state(self.state)
            except Exception as e:  # noqa: BLE001
                print(f"[sensor] tick error: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
            time.sleep(TICK_S)


# ── samples: ingest, fetch, summarise (shared with the API) ───────────────────────────────────────────────

def ingest_bytes(b: bytes, origin: str, settings: dict, name: str = "") -> dict:
    """Store + triage a sample; optionally detonate. Returns the static record."""
    from .. import triage
    config.ensure_dirs()
    sha = hashlib.sha256(b).hexdigest()
    p = os.path.join(config.SAMPLES, sha)
    is_new = not os.path.exists(p)
    if is_new:
        with open(p, "wb") as f:
            f.write(b)
        os.chmod(p, 0o400)
    rec = triage.triage_bytes(b, len(b), time.time())
    rec["origin"], rec["name"] = origin, (name or sha[:12])[:120]
    if not is_new:
        try:
            old = json.load(open(p + ".json", encoding="utf-8"))
            rec["first_seen"] = old.get("first_seen", rec["first_seen"])
            rec["origins"] = sorted(set((old.get("origins") or [old.get("origin")]) + [origin]))
        except (OSError, ValueError):
            pass
    rec.setdefault("origins", [origin])
    triage.save_record(config.SAMPLES, rec)
    config.event("sample_ingested", sha256=sha, kind=rec["kind"], arch=rec.get("arch"), origin=origin, new=is_new, verdict=rec.get("static_verdict"))
    if is_new and rec["kind"] == "elf" and settings["cell"].get("auto_detonate"):
        from .. import cell
        threading.Thread(target=cell.detonate, args=(sha, rec), daemon=True).start()
    return rec


def ingest_file(path: str, origin: str, settings: dict, name: str = "") -> dict:
    with open(path, "rb") as f:
        return ingest_bytes(f.read(config.MAX_SAMPLE_BYTES + 1)[:config.MAX_SAMPLE_BYTES], origin, settings, name)


def fetch_dropper(d: dict, settings: dict) -> dict | None:
    """Fetch a dropper URL into the sandbox with a throwaway container (never the host's own network stack)."""
    url = d["url"]
    cap = int(settings["cell"].get("max_fetch_mb", 8)) * 1024 * 1024
    tmp = os.path.join(config.SAMPLES, ".fetch-" + hashlib.sha1(url.encode()).hexdigest()[:12])
    os.makedirs(tmp, exist_ok=True)
    try:
        r = subprocess.run(["docker", "run", "--rm", "--network", "bridge", "--cap-drop", "ALL", "--memory", "64m", "--pids-limit", "16",
                            "-v", f"{_host(tmp)}:/out", "curlimages/curl:8.10.1", "-sS", "-L", "--max-time", "25", "--max-filesize", str(cap),
                            "--max-redirs", "3", "-A", "Mozilla/5.0", "-o", "/out/payload", url], capture_output=True, text=True, timeout=60)
        p = os.path.join(tmp, "payload")
        if r.returncode != 0 or not os.path.exists(p) or os.path.getsize(p) == 0:
            config.event("dropper_fetch_failed", url=url, rc=r.returncode, err=r.stderr[-160:])
            return None
        rec = ingest_file(p, origin=f"edge:{d.get('ip')}", settings=settings, name=url.rsplit("/", 1)[-1][:80] or "payload")
        rec["dropper"] = {"url": url, "seen_from": d.get("ip"), "family": d.get("family"), "cve": d.get("cve")}
        from .. import triage
        triage.save_record(config.SAMPLES, rec)
        config.event("dropper_fetched", url=url, sha256=rec["sha256"], kind=rec["kind"], arch=rec.get("arch"))
        return rec
    except Exception as e:  # noqa: BLE001
        config.event("dropper_fetch_failed", url=url, err=f"{type(e).__name__}: {e}"[:160])
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _host(p: str) -> str:
    from .. import cell
    return cell.host_path(p)


def samples_summary(limit: int = 500) -> List[dict]:
    from .. import cell
    out = []
    try:
        names = sorted((n for n in os.listdir(config.SAMPLES) if n.endswith(".json")), key=lambda n: -os.path.getmtime(os.path.join(config.SAMPLES, n)))
    except OSError:
        return out
    for n in names[:limit]:
        try:
            s = json.load(open(os.path.join(config.SAMPLES, n), encoding="utf-8"))
        except (OSError, ValueError):
            continue
        d = cell.load_detonation(s["sha256"]) or {}
        out.append({"sha256": s["sha256"], "name": s.get("name"), "kind": s.get("kind"), "arch": s.get("arch"), "bits": s.get("bits"), "size": s.get("size"),
                    "first_seen": s.get("first_seen"), "origin": s.get("origin"), "origins": s.get("origins"), "static_verdict": s.get("static_verdict"),
                    "packer": s.get("packer"), "entropy": s.get("entropy"), "urls": (s.get("iocs") or {}).get("urls", [])[:3],
                    "detonated": d.get("detonated"), "status": (d.get("run") or {}).get("status"), "verdict": d.get("verdict"),
                    "c2_candidates": d.get("c2_candidates"), "c2_extracted": d.get("c2_extracted"), "attack": [a["technique"] for a in d.get("attack") or []][:6],
                    "dropper": s.get("dropper")})
    return out


if __name__ == "__main__":
    Sensor().run_forever()
