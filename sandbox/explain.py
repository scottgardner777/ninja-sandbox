"""BYOK write-up on top of the deterministic report (S4).

Providers: `anthropic` (the official SDK, model default claude-opus-5-5, server-side refusal fallback on) and
`openai-compatible` (any /v1/chat/completions server: llama.cpp, vLLM, Ollama, LM Studio, or Ninja Cortex when
Ninja-hosted). No key configured -> the deterministic `summary` lines are the report and nothing is called.

The prompt carries ONLY the report JSON (hashes, structure, syscalls, endpoints, strings excerpts); never the
sample bytes. The write-up is labelled as model output in the UI and never changes the verdict fields.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict

from . import config

SYSTEM = ("You are a malware reverse engineer writing for a SOC analyst. You are given a JSON report from a sandbox: "
          "static triage of an ELF (structure, imports, strings, IOCs) and a 60-second detonation trace (syscalls, processes, "
          "files, network, C2 ranking, ATT&CK hints). Write a tight analyst note: 1) what this is (family guess with confidence "
          "and WHY from the evidence), 2) what it does step by step as observed, 3) C2 and infrastructure, 4) detection and "
          "containment: concrete indicators, Suricata/YARA-style hints, what to block, 5) what remains unknown. Cite the evidence "
          "field for each claim. Never invent indicators that are not in the report. Plain prose with short headings; under 500 words.")


def _slim(report: Dict[str, Any]) -> Dict[str, Any]:
    s, d = report.get("static") or {}, report.get("dynamic") or {}
    slim = {"sha256": report.get("sha256"), "static": {k: s.get(k) for k in ("kind", "arch", "bits", "size", "entropy", "packer", "static_verdict", "credentials")},
            "elf": {k: (s.get("elf") or {}).get(k) for k in ("summary", "needed", "imports", "section_names", "interp", "rwx_segment")},
            "iocs": s.get("iocs"), "interesting_strings": (s.get("interesting_strings") or [])[:60],
            "dynamic": {k: d.get(k) for k in ("verdict", "c2_likely", "c2_protocol", "dns", "scan_targets", "scan_ports", "top_targets", "sinkhole_hits",
                                               "procs", "files", "self_deleted", "binds", "attack", "syscalls", "exit", "errors", "timeout_s")},
            "summary_lines": report.get("summary")}
    if slim["dynamic"].get("sinkhole_hits"):
        slim["dynamic"]["sinkhole_hits"] = slim["dynamic"]["sinkhole_hits"][:12]
    if slim["dynamic"].get("syscalls"):
        sc = slim["dynamic"]["syscalls"]
        slim["dynamic"]["syscalls"] = dict(sorted(sc.items(), key=lambda kv: -kv[1])[:30])
    return slim


def explain(report: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    byok = settings.get("byok") or {}
    provider = byok.get("provider") or "none"
    user = "Sandbox report (JSON):\n" + json.dumps(_slim(report), ensure_ascii=False)
    if provider == "anthropic":
        return _anthropic(byok, user)
    if provider == "openai-compatible":
        return _openai_compatible(byok, user)
    return {"ok": False, "provider": "none", "text": "\n".join(report.get("summary") or []), "note": "No BYOK key: deterministic report only. Add one under Settings."}


def _anthropic(byok: Dict[str, Any], user: str) -> Dict[str, Any]:
    try:
        import anthropic
    except ImportError:
        return {"ok": False, "provider": "anthropic", "text": "", "error": "the anthropic package is not installed in this image"}
    model = byok.get("model") or "claude-opus-5-5"
    client = anthropic.Anthropic(api_key=byok.get("api_key") or None, max_retries=2, timeout=180.0)
    try:
        # server-side refusal fallback: a cyber safety decline re-runs on the default fallback model inside the same call
        resp = client.beta.messages.create(model=model, max_tokens=4096, system=SYSTEM, betas=["server-side-fallback-2026-07-01"],
                                           fallbacks="default", output_config={"effort": "medium"},
                                           messages=[{"role": "user", "content": user}])
    except anthropic.AuthenticationError:
        return {"ok": False, "provider": "anthropic", "text": "", "error": "Anthropic rejected the API key"}
    except anthropic.RateLimitError as e:
        return {"ok": False, "provider": "anthropic", "text": "", "error": f"rate limited: retry after {e.response.headers.get('retry-after', '?')}s"}
    except anthropic.BadRequestError as e:
        return {"ok": False, "provider": "anthropic", "text": "", "error": f"bad request: {e.message}"[:300]}
    except anthropic.APIStatusError as e:
        return {"ok": False, "provider": "anthropic", "text": "", "error": f"API error {e.status_code}: {e.message}"[:300]}
    except anthropic.APIConnectionError as e:
        return {"ok": False, "provider": "anthropic", "text": "", "error": f"connection error: {e}"[:300]}
    if resp.stop_reason == "refusal":
        cat = getattr(getattr(resp, "stop_details", None), "category", None)
        return {"ok": False, "provider": "anthropic", "text": "", "error": f"the model declined ({cat or 'refusal'}); the deterministic report stands"}
    text = "".join(b.text for b in resp.content if b.type == "text")
    served = resp.model
    return {"ok": True, "provider": "anthropic", "model": served, "text": text, "usage": {"in": resp.usage.input_tokens, "out": resp.usage.output_tokens},
            "fallback_used": served != model}


def _openai_compatible(byok: Dict[str, Any], user: str) -> Dict[str, Any]:
    base = (byok.get("base_url") or "").rstrip("/")
    if not base:
        return {"ok": False, "provider": "openai-compatible", "text": "", "error": "set base_url (e.g. http://llama:8080/v1)"}
    body = {"model": byok.get("model") or "default", "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
            "max_tokens": 1500, "temperature": 0.2}
    hdr = {"Content-Type": "application/json"}
    if byok.get("api_key"):
        hdr["Authorization"] = "Bearer " + byok["api_key"]
    try:
        req = urllib.request.Request(base + "/chat/completions", json.dumps(body).encode(), hdr)
        with urllib.request.urlopen(req, timeout=300) as r:
            d = json.loads(r.read())
        text = d["choices"][0]["message"]["content"]
        return {"ok": True, "provider": "openai-compatible", "model": d.get("model") or body["model"], "text": text, "usage": d.get("usage")}
    except urllib.error.HTTPError as e:
        return {"ok": False, "provider": "openai-compatible", "text": "", "error": f"HTTP {e.code}: {e.read(300).decode('utf-8', 'replace')}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "provider": "openai-compatible", "text": "", "error": f"{type(e).__name__}: {e}"[:300]}


def save(sha: str, result: Dict[str, Any]) -> None:
    import os
    with open(os.path.join(config.DETONATIONS, f"{sha}.explain.json"), "w", encoding="utf-8") as f:
        json.dump({**result, "at": config.now_iso()}, f, ensure_ascii=False, indent=1)


def load(sha: str):
    import os
    try:
        return json.load(open(os.path.join(config.DETONATIONS, f"{sha}.explain.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return None
