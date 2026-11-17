"""Deep Scan: a frontier model in the loop on one detonation.

(Scott, 17 Nov: "wire in mythos deep scan so we can do with you on it for interpreting outputs".)

A per-sample conversation with Claude over the FULL report: static triage, ELF structure, strings, IOCs, the
syscall timeline, processes, files, sinkhole hits with the first bytes sent, C2 ranking and ATT&CK hints. Streamed
to the UI as server-sent events; the transcript is kept beside the detonation as `<sha>.deepscan.json` with
`provenance: claude` (D7: model output is never training data).

Model:  SANDBOX_DEEP_MODEL   (default claude-fable-5-2; claude-mythos-5-2 is the same model for verified organisations) with
        SANDBOX_DEEP_FALLBACK (default claude-opus-5-5) when the organisation has no access, the model is unknown,
        or it declines. Adaptive thinking, high effort, prompt-cached context.
Key:    the house key (ANTHROPIC_API_KEY in the sandbox's environment: Ninja-hosted), else the BYOK Anthropic key.
Cap:    SANDBOX_DEEP_DAILY_CAP turns per day (default 40) so a shared instance cannot burn the house key.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

from . import config, explain, reverse

SYSTEM = (
    "You are a senior malware reverse engineer sitting with an analyst at the Ninja Sandbox console. You have the full "
    "report for ONE sample as JSON: static triage, ELF structure, strings, IOCs, and a 60-second detonation trace (syscall "
    "timeline, processes, files, sinkhole hits with the first bytes sent, C2 ranking, ATT&CK hints). The sample ran in a "
    "cell with no egress: every DNS answer was the sinkhole and every connect() succeeded against the sinkhole, so "
    "'connected' never means the real C2 was alive, and bytes the sample sent are what it would have sent to its C2. "
    "For foreign-architecture runs (tracer qemu) socket addresses in the strace are undecoded; the sinkhole log is the "
    "source of truth for the network.\n"
    "Rules: cite the report field for every claim (e.g. dynamic.sinkhole_hits[0].head). Separate what the evidence proves "
    "from what you infer, and give a confidence. Never invent an indicator, family name, or capability that the report "
    "does not support. When asked for detections, write YARA / Suricata-style rules only from bytes and strings that are "
    "in the report, and say what each rule would miss. Be concise: short headings, tight prose, no filler, no preamble. "
    "Answer follow-ups directly in the same evidence-first voice; the analyst may ask you to compare, hypothesise, or "
    "plan what to look at next in the pcap, strace, or strings."
)

OPENING = ("Deep scan this sample. 1) What it is and your confidence, from the evidence. 2) What the trace proves it did, "
           "step by step. 3) C2 and infrastructure: endpoints, protocol, what the first bytes tell us. 4) What you would "
           "look at next in the pcap, strace and strings, and why. 5) Detections that follow from the evidence (YARA and "
           "Suricata-style) with what they would miss. Cite fields.")

_lock = threading.Lock()


class ModelUnavailable(Exception):
    """The requested model cannot be used by this key (unknown id, no access): the caller falls back."""


def _key(settings: Dict[str, Any]) -> Dict[str, str]:
    if config.DEEP_KEY:
        return {"source": "house", "key": config.DEEP_KEY, "model": config.DEEP_MODEL}
    byok = settings.get("byok") or {}
    if byok.get("provider") == "anthropic" and byok.get("api_key"):
        return {"source": "byok", "key": byok["api_key"], "model": byok.get("model") or config.DEEP_MODEL}
    return {"source": "none", "key": "", "model": ""}


def _quota_path() -> str:
    return os.path.join(config.DATA, "deepscan_quota.json")


def _quota() -> Dict[str, Any]:
    day = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        q = json.load(open(_quota_path(), encoding="utf-8"))
    except (OSError, ValueError):
        q = {}
    if q.get("day") != day:
        q = {"day": day, "used": 0}
    return q


def _quota_take() -> bool:
    config.ensure_dirs()
    with _lock:
        q = _quota()
        if q["used"] >= config.DEEP_DAILY_CAP:
            return False
        q["used"] += 1
        with open(_quota_path(), "w", encoding="utf-8") as f:
            json.dump(q, f)
    return True


def available(settings: Dict[str, Any]) -> Dict[str, Any]:
    k = _key(settings)
    q = _quota()
    return {"available": k["source"] != "none", "source": k["source"], "model": k["model"], "fallback": config.DEEP_FALLBACK,
            "cap": config.DEEP_DAILY_CAP, "used_today": q["used"]}


def _path(sha: str) -> str:
    return os.path.join(config.DETONATIONS, f"{sha}.deepscan.json")


def load(sha: str) -> Optional[Dict[str, Any]]:
    try:
        return json.load(open(_path(sha), encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _save(sha: str, doc: Dict[str, Any]) -> None:
    config.ensure_dirs()
    with _lock:
        tmp = _path(sha) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
        os.replace(tmp, _path(sha))


def reset(sha: str) -> None:
    try:
        os.remove(_path(sha))
    except OSError:
        pass


def context(sha: str) -> str:
    """The report slice the model sees: explain's slim view plus the timeline, every sinkhole hit, and more strings."""
    rep = reverse.report(sha)
    slim = explain._slim(rep)
    d = rep.get("dynamic") or {}
    s = rep.get("static") or {}
    slim["dynamic"]["timeline"] = (d.get("timeline") or [])[:200]
    slim["dynamic"]["sinkhole_hits"] = (d.get("sinkhole_hits") or [])[:40]
    slim["dynamic"]["udp_payloads"] = (d.get("udp_payloads") or [])[:20]
    slim["dynamic"]["writes_sample"] = (d.get("writes_sample") or [])[:20]
    slim["dynamic"]["run"] = d.get("run")
    slim["interesting_strings"] = (s.get("interesting_strings") or [])[:160]
    e = s.get("elf") or {}
    slim["elf"]["segments"] = e.get("segments")
    slim["elf"]["sections"] = [{k: x.get(k) for k in ("name", "type", "size", "entropy")} for x in (e.get("sections") or []) if x.get("name")][:40]
    slim["elf"]["exports"] = (e.get("exports") or [])[:40]
    return json.dumps(slim, ensure_ascii=False)


def _stream_model(model: str, key: str, system: List[Dict[str, Any]], messages: List[Dict[str, str]]) -> Iterator[Dict[str, Any]]:
    """Yield {"type": "text"} chunks then one {"type": "done"}; raise ModelUnavailable when the id/key pairing cannot run."""
    import anthropic
    client = anthropic.Anthropic(api_key=key, max_retries=1, timeout=600.0)
    try:
        with client.messages.stream(model=model, max_tokens=8000, system=system, messages=messages,
                                    thinking={"type": "adaptive"}, output_config={"effort": "high"}) as stream:
            for text in stream.text_stream:
                yield {"type": "text", "text": text}
            final = stream.get_final_message()
    except anthropic.NotFoundError as e:
        raise ModelUnavailable(f"{model}: {e.message}"[:200]) from e
    except anthropic.PermissionDeniedError as e:
        raise ModelUnavailable(f"{model}: {e.message}"[:200]) from e
    except anthropic.BadRequestError as e:
        if "model" in (e.message or "").lower():
            raise ModelUnavailable(f"{model}: {e.message}"[:200]) from e
        raise
    stop = final.stop_reason
    cat = getattr(getattr(final, "stop_details", None), "category", None) if stop == "refusal" else None
    yield {"type": "done", "model": final.model, "stop": stop, "category": cat,
           "usage": {"in": final.usage.input_tokens, "out": final.usage.output_tokens,
                     "cached": getattr(final.usage, "cache_read_input_tokens", 0) or 0}}


def _sse(ev: Dict[str, Any]) -> str:
    return "data: " + json.dumps(ev, ensure_ascii=False) + "\n\n"


def turn(sha: str, message: str, settings: Dict[str, Any]) -> Iterator[str]:
    """One analyst turn: append it, stream the model's reply, persist both. Yields SSE lines."""
    k = _key(settings)
    if k["source"] == "none":
        yield _sse({"type": "error", "error": "Deep Scan needs a key: the house key (ANTHROPIC_API_KEY) or a BYOK Anthropic key in Settings."})
        return
    doc = load(sha) or {"sha256": sha, "provenance": "claude", "turns": []}
    message = (message or "").strip() or (OPENING if not doc["turns"] else "Continue.")
    if not _quota_take():
        yield _sse({"type": "error", "error": f"daily Deep Scan cap reached ({config.DEEP_DAILY_CAP} turns); try tomorrow"})
        return
    try:
        ctx = context(sha)
    except Exception as e:  # noqa: BLE001
        yield _sse({"type": "error", "error": f"no report for this sample: {e}"[:200]})
        return
    system = [{"type": "text", "text": SYSTEM},
              {"type": "text", "text": "Sandbox report (JSON):\n" + ctx, "cache_control": {"type": "ephemeral"}}]
    history = [{"role": t["role"], "content": t["content"]} for t in doc["turns"] if t.get("content")]
    history.append({"role": "user", "content": message})
    doc["turns"].append({"role": "user", "content": message, "at": config.now_iso()})
    yield _sse({"type": "start", "model": k["model"], "source": k["source"], "message": message})

    def run(model: str) -> Iterator[Dict[str, Any]]:
        return _stream_model(model, k["key"], system, history)

    text, meta, tried = "", None, [k["model"]]
    try:
        import anthropic
    except ImportError:
        yield _sse({"type": "error", "error": "the anthropic package is not installed in this image"})
        return
    try:
        try:
            for ev in run(k["model"]):
                if ev["type"] == "text":
                    text += ev["text"]
                    yield _sse(ev)
                else:
                    meta = ev
        except ModelUnavailable as e:
            yield _sse({"type": "restart", "why": str(e), "model": config.DEEP_FALLBACK})
            text, meta = "", None
            tried.append(config.DEEP_FALLBACK)
            for ev in run(config.DEEP_FALLBACK):
                if ev["type"] == "text":
                    text += ev["text"]
                    yield _sse(ev)
                else:
                    meta = ev
        if meta and meta.get("stop") == "refusal" and config.DEEP_FALLBACK not in tried:
            yield _sse({"type": "restart", "why": f"{meta['model']} declined ({meta.get('category') or 'refusal'})", "model": config.DEEP_FALLBACK})
            text, meta = "", None
            tried.append(config.DEEP_FALLBACK)
            for ev in run(config.DEEP_FALLBACK):
                if ev["type"] == "text":
                    text += ev["text"]
                    yield _sse(ev)
                else:
                    meta = ev
    except anthropic.AuthenticationError:
        yield _sse({"type": "error", "error": "Anthropic rejected the API key"})
        return
    except anthropic.RateLimitError as e:
        yield _sse({"type": "error", "error": f"rate limited: retry after {e.response.headers.get('retry-after', '?')}s"})
        return
    except anthropic.APIStatusError as e:
        yield _sse({"type": "error", "error": f"API error {e.status_code}: {e.message}"[:300]})
        return
    except anthropic.APIConnectionError as e:
        yield _sse({"type": "error", "error": f"connection error: {e}"[:300]})
        return
    except ModelUnavailable as e:
        yield _sse({"type": "error", "error": f"no usable model: {e}"[:300]})
        return
    if meta and meta.get("stop") == "refusal":
        yield _sse({"type": "error", "error": f"the model declined ({meta.get('category') or 'refusal'}); the deterministic report stands"})
        doc["turns"].pop()
        _save(sha, doc)
        return
    doc["turns"].append({"role": "assistant", "content": text, "at": config.now_iso(), "model": (meta or {}).get("model"),
                         "usage": (meta or {}).get("usage"), "fallback_used": bool(meta and meta.get("model") != k["model"])})
    doc["model"] = (meta or {}).get("model")
    _save(sha, doc)
    config.event("deepscan", sha256=sha, model=(meta or {}).get("model"), turns=len(doc["turns"]), usage=(meta or {}).get("usage"))
    yield _sse({"type": "done", "model": (meta or {}).get("model"), "usage": (meta or {}).get("usage"),
                "fallback_used": bool(meta and meta.get("model") != k["model"]), "turns": len(doc["turns"])})
