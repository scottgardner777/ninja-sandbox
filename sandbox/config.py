"""Paths, settings and environment knobs for Ninja Sandbox.

Everything lives under one data directory (SANDBOX_DATA, default /data in the container, ./data on a dev box):

  samples/<sha256>              the bytes (never executed on the host; the cell copies them into a runner)
  samples/<sha256>.json         static triage + origin (upload | watch:<dir> | edge:<ip> | api)
  detonations/<sha256>.json     the cell's record (run + analysis); .strace.txt / .pcap / .sinkhole.jsonl beside it
  sensor/sensor.json            the Raz0r Sensor's current picture (per-IP aggregates, probe families, DNA)
  sensor/droppers.jsonl         dropper URLs seen in attack traffic (what the sensor would load in situ)
  sensor/requests.jsonl         the last N requests (bounded) the DNA profiles are built from; raw lines never leave the box
  settings.json                 mode / BYOK / telemetry / watch dirs / auto-detonate: edited from the UI's Settings tab
  events.jsonl                  append-only activity log the UI shows

Settings never contain anything the UI would not show. The BYOK key is stored here on the user's box only and is
returned to the UI masked (last 4 characters).
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict

DATA = os.environ.get("SANDBOX_DATA", "/data" if os.path.isdir("/data") else os.path.join(os.getcwd(), "data"))
# When the API runs in a container and drives sibling containers through the Docker socket, bind mounts for
# the cell must use HOST paths. SANDBOX_HOST_DATA is the host path of DATA (compose sets it to ${PWD}/data).
HOST_DATA = os.environ.get("SANDBOX_HOST_DATA", DATA)
SAMPLES = os.path.join(DATA, "samples")
DETONATIONS = os.path.join(DATA, "detonations")
SENSOR = os.path.join(DATA, "sensor")
SETTINGS_F = os.path.join(DATA, "settings.json")
EVENTS_F = os.path.join(DATA, "events.jsonl")

MODES = ("self-hosted", "ninja-hosted", "hybrid")
MAX_SAMPLE_BYTES = int(os.environ.get("SANDBOX_MAX_SAMPLE_MB", "32")) * 1024 * 1024
TOKEN = os.environ.get("SANDBOX_TOKEN", "")          # empty = no auth (bind to 127.0.0.1 then)
TELEMETRY_URL = os.environ.get("SANDBOX_TELEMETRY_URL", "https://ninjalabz.io/api/sandbox/telemetry")
HOSTED = bool(os.environ.get("SANDBOX_HOSTED"))     # the Ninja-hosted instance behind Labz auth (settings admin-only at the gate)
# Deep Scan (a frontier model in the loop on one detonation): house key = Ninja-hosted; self-hosted uses the BYOK key
DEEP_MODEL = os.environ.get("SANDBOX_DEEP_MODEL", "claude-mythos-5-1")
DEEP_FALLBACK = os.environ.get("SANDBOX_DEEP_FALLBACK", "claude-opus-5-5")
DEEP_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
DEEP_DAILY_CAP = int(os.environ.get("SANDBOX_DEEP_DAILY_CAP", "40"))

DEFAULT_SETTINGS: Dict[str, Any] = {
    "mode": os.environ.get("SANDBOX_MODE", "self-hosted"),
    "telemetry": {
        # S3: OFF in self-hosted, on in ninja-hosted. What is sent is exactly what /api/sandbox/telemetry/preview shows:
        # per-IP aggregates (the sensor's deltas) + sample hashes/verdicts. Never raw log lines, never sample bytes
        # unless share_samples is ticked.
        "enabled": os.environ.get("SANDBOX_MODE", "self-hosted") == "ninja-hosted",
        "share_samples": False,
        "url": TELEMETRY_URL,
        "install_id": "",
    },
    "byok": {
        # S4: Anthropic, or any OpenAI-compatible endpoint (llama.cpp, vLLM, Ollama). No key = deterministic report only.
        "provider": "none",            # none | anthropic | openai-compatible
        "model": "",
        "base_url": "",                # openai-compatible only, e.g. http://ninja-cortex-llm:18041/v1
        "api_key": "",
    },
    "cell": {
        "timeout_s": 60,
        "auto_detonate": False,        # detonate every new ELF sample as it lands (uploads, watch dirs, fetched droppers)
        "fetch_droppers": False,       # fetch dropper URLs the sensor sees at the edge, into the sandbox (size-capped, never run on host)
        "max_fetch_mb": 8,
        "retention_days": 0,           # 0 = keep everything (self-hosted); ninja-hosted free tier sets 7
    },
    "sensor": {
        "input": os.environ.get("SENSOR_INPUT", "file"),   # file | syslog | inline
        "format": os.environ.get("SENSOR_FORMAT", "caddy"),  # caddy | nginx | apache | traefik | auto
        "log_paths": [p for p in os.environ.get("SENSOR_LOG_PATHS", "").split(",") if p],
        "watch_dirs": [p for p in os.environ.get("SANDBOX_WATCH_DIRS", "").split(",") if p],
        "exclude": [p for p in os.environ.get("SENSOR_EXCLUDE", "").split(",") if p],   # owner IPs / CIDRs
        "retain_requests": 200000,
    },
}

_lock = threading.Lock()


def ensure_dirs() -> None:
    for d in (DATA, SAMPLES, DETONATIONS, SENSOR):
        os.makedirs(d, exist_ok=True)


def _merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_settings() -> Dict[str, Any]:
    try:
        with open(SETTINGS_F, encoding="utf-8") as f:
            s = _merge(DEFAULT_SETTINGS, json.load(f))
    except (OSError, ValueError):
        s = json.loads(json.dumps(DEFAULT_SETTINGS))
    if s.get("mode") not in MODES:
        s["mode"] = "self-hosted"
    if not s["telemetry"].get("install_id"):
        s["telemetry"]["install_id"] = os.urandom(8).hex()
        save_settings(s)
    return s


def save_settings(s: Dict[str, Any]) -> None:
    ensure_dirs()
    with _lock:
        tmp = SETTINGS_F + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
        os.replace(tmp, SETTINGS_F)


def public_settings(s: Dict[str, Any]) -> Dict[str, Any]:
    """What the UI gets: the BYOK key masked."""
    out = json.loads(json.dumps(s))
    key = out["byok"].get("api_key") or ""
    out["byok"]["api_key"] = ("…" + key[-4:]) if key else ""
    out["byok"]["has_key"] = bool(key)
    return out


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def event(name: str, **fields: Any) -> None:
    ensure_dirs()
    rec = {"ts": now_iso(), "kind": name, **{("sample_kind" if k == "kind" else k): v for k, v in fields.items() if k != "ts"}}
    with _lock, open(EVENTS_F, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def events(limit: int = 100):
    try:
        with open(EVENTS_F, encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            pass
    return out[::-1]
