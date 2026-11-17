"""Deep Scan: the streamed turn, fallback, persistence with provenance, the daily cap, and 'no key' refusal.
The model call is stubbed; nothing is sent anywhere."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_sandbox import minimal_elf  # noqa: E402


def _events(body: str):
    return [json.loads(ln[6:]) for ln in body.split("\n") if ln.startswith("data: ")]


def test_deepscan_turns(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_DATA", str(tmp_path / "d"))
    for m in [m for m in list(sys.modules) if m.startswith("sandbox")]:
        del sys.modules[m]
    from fastapi.testclient import TestClient
    from sandbox import api, config, deepscan
    c = TestClient(api.app)
    sha = c.post("/api/sandbox/samples", files={"file": ("bot.x86", minimal_elf(needed=["libc.so.6"]))}).json()["sample"]["sha256"]

    # no key anywhere -> not available, the turn says so and stores nothing
    monkeypatch.setattr(config, "DEEP_KEY", "")
    assert c.get("/api/sandbox/status").json()["deepscan"]["available"] is False
    evs = _events(c.post(f"/api/sandbox/deepscan/{sha}", json={"message": "what is it"}).text)
    assert evs[-1]["type"] == "error" and "key" in evs[-1]["error"] and deepscan.load(sha) is None

    # house key + stubbed model: first call on the primary id is "unknown" -> fallback streams the answer
    monkeypatch.setattr(config, "DEEP_KEY", "sk-house")
    monkeypatch.setattr(config, "DEEP_MODEL", "claude-mythos-5-1")
    monkeypatch.setattr(config, "DEEP_FALLBACK", "claude-opus-5-5")
    calls = []

    def fake_stream(model, key, system, messages):
        calls.append((model, key, len(messages), messages[-1]["content"]))
        assert system[1]["cache_control"] == {"type": "ephemeral"} and '"sha256"' in system[1]["text"]
        if model == "claude-mythos-5-1":
            raise deepscan.ModelUnavailable("claude-mythos-5-1: not found")
        yield {"type": "text", "text": "It is a "}
        yield {"type": "text", "text": "test ELF."}
        yield {"type": "done", "model": model, "stop": "end_turn", "category": None, "usage": {"in": 10, "out": 5, "cached": 0}}
    monkeypatch.setattr(deepscan, "_stream_model", fake_stream)
    st = c.get("/api/sandbox/status").json()["deepscan"]
    assert st == {"available": True, "source": "house", "model": "claude-mythos-5-1", "fallback": "claude-opus-5-5", "cap": config.DEEP_DAILY_CAP, "used_today": 0}
    r = c.post(f"/api/sandbox/deepscan/{sha}", json={})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    evs = _events(r.text)
    kinds = [e["type"] for e in evs]
    assert kinds == ["start", "restart", "text", "text", "done"]
    assert evs[0]["message"].startswith("Deep scan this sample") and evs[1]["model"] == "claude-opus-5-5"
    assert evs[-1]["model"] == "claude-opus-5-5" and evs[-1]["fallback_used"] is True and evs[-1]["turns"] == 2
    assert [m for m, *_ in calls] == ["claude-mythos-5-1", "claude-opus-5-5"] and calls[0][1] == "sk-house"
    doc = deepscan.load(sha)
    assert doc["provenance"] == "claude" and doc["turns"][1]["content"] == "It is a test ELF." and doc["turns"][1]["model"] == "claude-opus-5-5"

    # second turn carries the history (3 messages: user, assistant, user)
    evs = _events(c.post(f"/api/sandbox/deepscan/{sha}", json={"message": "write yara"}).text)
    assert evs[-1]["turns"] == 4 and calls[-1][2] == 3 and calls[-1][3] == "write yara"
    g = c.get(f"/api/sandbox/deepscan/{sha}").json()
    assert len(g["transcript"]["turns"]) == 4 and g["used_today"] == 2
    assert any(e["kind"] == "deepscan" for e in c.get("/api/sandbox/events").json()["events"])

    # the cap
    monkeypatch.setattr(config, "DEEP_DAILY_CAP", 2)
    evs = _events(c.post(f"/api/sandbox/deepscan/{sha}", json={"message": "more"}).text)
    assert evs[-1]["type"] == "error" and "cap" in evs[-1]["error"]
    # reset forgets the transcript
    assert c.post(f"/api/sandbox/deepscan/{sha}", json={"reset": True}).json()["ok"] is True and deepscan.load(sha) is None
    # unknown sample
    assert c.post("/api/sandbox/deepscan/" + "0" * 64, json={}).status_code == 404


def test_deepscan_refusal_then_fallback_declines(monkeypatch, tmp_path):
    monkeypatch.setenv("SANDBOX_DATA", str(tmp_path / "d"))
    for m in [m for m in list(sys.modules) if m.startswith("sandbox")]:
        del sys.modules[m]
    from fastapi.testclient import TestClient
    from sandbox import api, config, deepscan
    c = TestClient(api.app)
    sha = c.post("/api/sandbox/samples", files={"file": ("bot.x86", minimal_elf())}).json()["sample"]["sha256"]
    monkeypatch.setattr(config, "DEEP_KEY", "sk-house")

    def refusing(model, key, system, messages):
        yield {"type": "done", "model": model, "stop": "refusal", "category": "cyber", "usage": {"in": 1, "out": 0, "cached": 0}}
    monkeypatch.setattr(deepscan, "_stream_model", refusing)
    evs = _events(c.post(f"/api/sandbox/deepscan/{sha}", json={}).text)
    assert [e["type"] for e in evs] == ["start", "restart", "error"] and "declined" in evs[-1]["error"]
    assert deepscan.load(sha)["turns"] == []        # the unanswered question is not kept
