"""Ninja Sandbox API + the single-page UI.

    GET  /                                     the UI
    GET  /api/sandbox/status                   cell readiness (docker, images, binfmt), counts, mode, version
    GET  /api/sandbox/samples                  list (static + detonation summary)
    POST /api/sandbox/samples                  upload (multipart `file`) or {"url": ...} fetch (opt-in fetcher) or {"hash": ...} lookup
    GET  /api/sandbox/samples/{sha}            the static record
    DELETE /api/sandbox/samples/{sha}
    POST /api/sandbox/detonate/{sha}           run the cell (background); ?wait=1 blocks until done
    GET  /api/sandbox/report/{sha}             the Reverse tab payload (static + dynamic + summary + explain if any)
    GET  /api/sandbox/report/{sha}/strings     full strings
    GET  /api/sandbox/report/{sha}/hex?offset= hexdump window
    GET  /api/sandbox/artifact/{sha}/{kind}    strace.txt | sinkhole.jsonl | pcap | stdout.txt (download)
    POST /api/sandbox/explain/{sha}            BYOK write-up
    GET  /api/sandbox/sensor                   the sensor picture (aggregates + DNA + droppers)
    GET  /api/sandbox/sensor/ip/{ip}           one IP's DNA profile + its requests
    GET  /api/sandbox/sensor/compare?a=&b=     same-operator check
    POST /api/sandbox/sensor/ingest            push log lines (JSON {"lines": [...], "format": "caddy"}) from anywhere
    POST /api/sandbox/droppers/{idx}/fetch     fetch one seen dropper URL into the sandbox
    GET  /api/sandbox/settings  PUT            mode / BYOK / telemetry / cell / sensor
    GET  /api/sandbox/telemetry/preview        the exact JSON that WOULD be sent
    GET  /api/sandbox/events                   activity log
    POST /api/sandbox/cell/build               build the cell images (long)

Auth: when SANDBOX_TOKEN is set, every /api route needs X-Sandbox-Token (or ?token=). Ninja-hosted mode sits
behind Labz auth instead and sets the token per tenant.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from . import __version__, cell, config, dna, explain as explain_mod, reverse, triage
from .sensor import core as sensor_core, parsers, run as sensor_run

app = FastAPI(title="Ninja Sandbox", version=__version__, docs_url="/api/docs", redoc_url=None)
HERE = os.path.dirname(os.path.abspath(__file__))
UI = os.path.join(os.path.dirname(HERE), "ui", "index.html")
CELL_DIR = os.path.join(os.path.dirname(HERE), "cell")
_jobs: Dict[str, Dict[str, Any]] = {}
SHA_RE = __import__("re").compile(r"^[0-9a-f]{64}$")


@app.middleware("http")
async def _auth(request: Request, call_next):
    if config.TOKEN and request.url.path.startswith("/api/"):
        tok = request.headers.get("X-Sandbox-Token") or request.query_params.get("token") or ""
        if tok != config.TOKEN:
            return JSONResponse({"detail": "sandbox token"}, 401)
    return await call_next(request)


def _sha(sha: str) -> str:
    sha = (sha or "").lower()
    if not SHA_RE.match(sha):
        raise HTTPException(400, "sha256 expected")
    return sha


def _static(sha: str) -> Dict[str, Any]:
    try:
        with open(os.path.join(config.SAMPLES, sha + ".json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        raise HTTPException(404, "no such sample")


@app.get("/", response_class=HTMLResponse)
def ui():
    with open(UI, encoding="utf-8") as f:
        return f.read()


@app.get("/api/sandbox/status")
def status():
    config.ensure_dirs()
    s = config.load_settings()
    samples = sensor_run.samples_summary(limit=5000)
    pic = _picture()
    return {"version": __version__, "mode": s["mode"], "cell": cell.docker_ok(), "samples": len(samples),
            "detonated": sum(1 for x in samples if x.get("detonated")), "c2_extracted": sum(1 for x in samples if x.get("c2_extracted")),
            "sensor": {"as_of": pic.get("as_of"), "ips": pic.get("ips"), "probing_ips": pic.get("probing_ips"), "droppers": len(pic.get("droppers") or []),
                       "input": pic.get("input"), "lines_seen": pic.get("lines_seen")},
            "jobs": {k: v for k, v in _jobs.items() if v.get("state") == "running"}, "telemetry": s["telemetry"]["enabled"], "auth": bool(config.TOKEN)}


# ── samples ───────────────────────────────────────────────────────────────────────────────────────────────
@app.get("/api/sandbox/samples")
def samples(limit: int = Query(200, ge=1, le=5000)):
    return {"samples": sensor_run.samples_summary(limit=limit)}


@app.post("/api/sandbox/samples")
async def upload(request: Request, file: Optional[UploadFile] = File(None)):
    s = config.load_settings()
    if file is not None:
        b = await file.read()
        if not b:
            raise HTTPException(400, "empty file")
        if len(b) > config.MAX_SAMPLE_BYTES:
            raise HTTPException(413, f"sample over {config.MAX_SAMPLE_BYTES >> 20} MiB")
        rec = sensor_run.ingest_bytes(b, origin="upload", settings=s, name=file.filename or "")
        return {"ok": True, "sample": rec, "auto_detonate": s["cell"]["auto_detonate"] and rec["kind"] == "elf"}
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    if body.get("url"):
        if not s["cell"].get("fetch_droppers"):
            raise HTTPException(403, "URL fetching is off: enable cell.fetch_droppers in Settings")
        rec = sensor_run.fetch_dropper({"url": str(body["url"])[:500], "ip": "manual"}, s)
        if not rec:
            raise HTTPException(502, "fetch failed (see events)")
        return {"ok": True, "sample": rec}
    if body.get("hash"):
        sha = _sha(body["hash"])
        return {"ok": True, "sample": _static(sha), "detonation": cell.load_detonation(sha)}
    raise HTTPException(400, "send multipart `file`, or JSON {url} / {hash}")


@app.get("/api/sandbox/samples/{sha}")
def sample(sha: str):
    sha = _sha(sha)
    return {"sample": _static(sha), "detonation": cell.load_detonation(sha), "explain": explain_mod.load(sha)}


@app.delete("/api/sandbox/samples/{sha}")
def delete_sample(sha: str):
    sha = _sha(sha)
    n = 0
    for d, names in ((config.SAMPLES, (sha, sha + ".json")), (config.DETONATIONS, tuple(f"{sha}{suf}" for suf in (".json", ".strace.txt", ".sinkhole.jsonl", ".pcap", ".stdout.txt", ".tmp_after.txt", ".explain.json")))):
        for nme in names:
            p = os.path.join(d, nme)
            if os.path.exists(p):
                os.chmod(p, 0o600)
                os.remove(p)
                n += 1
    config.event("sample_deleted", sha256=sha, files=n)
    return {"ok": True, "removed": n}


# ── detonation ────────────────────────────────────────────────────────────────────────────────────────────
def _run_job(sha: str, meta: Dict[str, Any]):
    _jobs[sha] = {"state": "running", "started": config.now_iso()}
    try:
        rec = cell.detonate(sha, meta)
        _jobs[sha] = {"state": "done", "finished": config.now_iso(), "status": rec.get("run", {}).get("status"), "verdict": rec.get("verdict")}
    except Exception as e:  # noqa: BLE001
        _jobs[sha] = {"state": "error", "error": f"{type(e).__name__}: {e}"[:300]}


@app.post("/api/sandbox/detonate/{sha}")
def detonate(sha: str, wait: int = Query(0, ge=0, le=1), timeout: Optional[int] = Query(None, ge=10, le=600)):
    sha = _sha(sha)
    meta = _static(sha)
    if meta.get("kind") != "elf":
        raise HTTPException(400, f"the cell runs Linux ELF; this sample is {meta.get('kind')} (static triage is on the Reverse tab)")
    ready = cell.docker_ok()
    if not ready["ready"]:
        raise HTTPException(503, {"detail": "cell not ready", "cell": ready})
    if _jobs.get(sha, {}).get("state") == "running":
        return {"ok": True, "job": _jobs[sha], "queued": False}
    if wait:
        rec = cell.detonate(sha, meta, timeout=timeout)
        return {"ok": True, "detonation": rec}
    threading.Thread(target=_run_job, args=(sha, meta), daemon=True).start()
    return {"ok": True, "job": _jobs.get(sha, {"state": "starting"}), "queued": True}


@app.get("/api/sandbox/jobs")
def jobs():
    return {"jobs": _jobs}


# ── the Reverse tab ───────────────────────────────────────────────────────────────────────────────────────
@app.get("/api/sandbox/report/{sha}")
def report(sha: str):
    sha = _sha(sha)
    rep = reverse.report(sha)
    if not rep.get("static"):
        raise HTTPException(404, "no such sample")
    rep["explain"] = explain_mod.load(sha)
    rep["job"] = _jobs.get(sha)
    return rep


@app.get("/api/sandbox/report/{sha}/strings")
def report_strings(sha: str):
    sha = _sha(sha)
    p = os.path.join(config.SAMPLES, sha)
    if not os.path.isfile(p):
        raise HTTPException(404, "no such sample")
    return triage.full_strings(p)


@app.get("/api/sandbox/report/{sha}/hex")
def report_hex(sha: str, offset: int = Query(0, ge=0), length: int = Query(1024, ge=16, le=16384)):
    sha = _sha(sha)
    p = os.path.join(config.SAMPLES, sha)
    if not os.path.isfile(p):
        raise HTTPException(404, "no such sample")
    return {"offset": offset, "size": os.path.getsize(p), "hex": triage.hexdump(p, length, offset)}


@app.get("/api/sandbox/artifact/{sha}/{kind}")
def artifact(sha: str, kind: str):
    sha = _sha(sha)
    if kind not in ("strace.txt", "sinkhole.jsonl", "pcap", "stdout.txt", "tmp_after.txt"):
        raise HTTPException(400, "kind")
    p = os.path.join(config.DETONATIONS, f"{sha}.{kind}")
    if not os.path.isfile(p):
        raise HTTPException(404, "no such artifact")
    media = "application/vnd.tcpdump.pcap" if kind == "pcap" else "text/plain"
    return FileResponse(p, media_type=media, filename=f"{sha[:16]}.{kind}")


@app.post("/api/sandbox/explain/{sha}")
def explain(sha: str):
    sha = _sha(sha)
    rep = reverse.report(sha)
    if not rep.get("static"):
        raise HTTPException(404, "no such sample")
    res = explain_mod.explain(rep, config.load_settings())
    if res.get("ok"):
        explain_mod.save(sha, res)
        config.event("explained", sha256=sha, provider=res.get("provider"), model=res.get("model"))
    return res


# ── the Sensor tab ────────────────────────────────────────────────────────────────────────────────────────
def _picture() -> Dict[str, Any]:
    try:
        with open(sensor_run.PICTURE_F, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"as_of": None, "ips": 0, "probing_ips": 0, "families": {}, "cves": {}, "top": [], "dna": {"summary": {}, "clusters": [], "narratives": []}, "droppers": []}


@app.get("/api/sandbox/sensor")
def sensor():
    return _picture()


@app.get("/api/sandbox/sensor/ip/{ip}")
def sensor_ip(ip: str):
    reqs = sensor_run.load_requests()
    return dna.profile_ip(reqs, ip)


@app.get("/api/sandbox/sensor/compare")
def sensor_compare(a: str, b: str):
    return dna.compare(sensor_run.load_requests(), a, b)


_ingest_sensor: Optional[sensor_run.Sensor] = None


@app.post("/api/sandbox/sensor/ingest")
async def sensor_ingest(request: Request):
    """Push lines from anywhere (a cron on another box, a log shipper). Same pipeline as the sensor service."""
    global _ingest_sensor
    body = await request.json()
    lines: List[str] = body.get("lines") or []
    if not isinstance(lines, list) or len(lines) > 50000:
        raise HTTPException(400, "lines: list of up to 50000 strings")
    if _ingest_sensor is None:
        _ingest_sensor = sensor_run.Sensor()
    _ingest_sensor.fmt = body.get("format") or "auto"
    before = _ingest_sensor.agg.kept
    for ln in lines:
        _ingest_sensor.on_line(str(ln)[:8000], "api")
    _ingest_sensor.picture()
    return {"ok": True, "kept": _ingest_sensor.agg.kept - before, "unparsed": _ingest_sensor.unparsed}


@app.post("/api/sandbox/droppers/fetch")
async def dropper_fetch(request: Request):
    body = await request.json()
    s = config.load_settings()
    if not s["cell"].get("fetch_droppers"):
        raise HTTPException(403, "URL fetching is off: enable cell.fetch_droppers in Settings")
    rec = sensor_run.fetch_dropper({"url": str(body.get("url"))[:500], "ip": body.get("ip") or "manual", "family": body.get("family"), "cve": body.get("cve")}, s)
    if not rec:
        raise HTTPException(502, "fetch failed (see events)")
    return {"ok": True, "sample": rec}


# ── settings / telemetry / events ─────────────────────────────────────────────────────────────────────────
@app.get("/api/sandbox/settings")
def get_settings():
    return config.public_settings(config.load_settings())


@app.put("/api/sandbox/settings")
async def put_settings(request: Request):
    body = await request.json()
    s = config.load_settings()
    for section in ("telemetry", "byok", "cell", "sensor"):
        if isinstance(body.get(section), dict):
            for k, v in body[section].items():
                if k in s[section] or k == "api_key":
                    if section == "byok" and k == "api_key" and (not v or str(v).startswith("…")):
                        continue      # masked value echoed back: keep the stored key
                    s[section][k] = v
    if body.get("mode") in config.MODES:
        s["mode"] = body["mode"]
    if body.get("byok", {}).get("clear_key"):
        s["byok"]["api_key"] = ""
    config.save_settings(s)
    config.event("settings_changed", keys=[k for k in body if k in ("mode", "telemetry", "byok", "cell", "sensor")])
    return config.public_settings(s)


@app.get("/api/sandbox/telemetry/preview")
def telemetry_preview():
    s = config.load_settings()
    rows = _picture().get("top") or []
    # the preview is built from the same function the sensor uses to send, on the current aggregate rows
    agg_rows = [{"ip": r["ip"], "req": r["req"], "first": r["first"], "last": r["last"], "cc": r.get("cc"), "sites": {h: {} for h in r.get("sites", [])},
                 "probes": {}, "ua": {r.get("ua") or "": r["req"]}, "status": r.get("status", {}), "droppers": r.get("droppers", [])} for r in rows[:50]]
    return {"enabled": s["telemetry"]["enabled"], "url": s["telemetry"].get("url"), "payload": sensor_run.telemetry_payload(agg_rows, s, sensor_run.samples_summary(20))}


@app.get("/api/sandbox/events")
def events(limit: int = Query(100, ge=1, le=1000)):
    return {"events": config.events(limit)}


@app.post("/api/sandbox/cell/build")
def cell_build():
    return cell.build_images(CELL_DIR)
