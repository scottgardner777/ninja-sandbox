# Copyright 2026 Scott Gardner, ninja.ing. Licensed under the Apache License, Version 2.0.
"""Adversary DNA: behavioural fingerprinting of every IP that hits an edge, from access-log entries alone.

Ported from Ninja Signal's core/adversary_dna.py (the 18-dimension fingerprint, archetype scoring, kill-chain
mapping, Markov next-move model, same-operator clustering and narrative) into the sandbox as plain code:

  1. behavioural fingerprinting: an 18-dimension feature vector per IP
  2. archetype classification: scanner, brute-forcer, researcher, bot-crawler, targeted operator (weighted scoring)
  3. kill-chain stage mapping with confidence
  4. Markov chain over path categories -> an attacker's likely next move (S7: trained on YOUR edge only)
  5. clustering by cosine similarity -> the same operator behind different IPs / VPNs (union-find, > 0.85)
  6. a human-readable narrative per attacker

Input is a list of flat request dicts (ts, host, path, uri, method, status, size, ip, user_agent) as produced by
sandbox.sensor.parsers, or raw Caddy JSON entries via `extract_caddy`. Pure Python + math; nothing leaves the box.
The Ninja graph attribution the Signal version does is NOT bundled: `attribution` is an optional callback the
Ninja-hosted mode plugs in; self-hosted installs with telemetry on get it through the "seen by Ninja" lookup.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

log = logging.getLogger("sandbox.dna")

MAX_CLUSTER_IPS = 600
_DEFAULT_EXCLUDE = ("10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10")


def exclusion_nets(extra: Iterable[str] = ()) -> tuple:
    nets = []
    for spec in tuple(_DEFAULT_EXCLUDE) + tuple(extra or ()):
        try:
            nets.append(ipaddress.ip_network(spec.strip(), strict=False))
        except ValueError:
            log.warning("exclude: ignoring invalid network %r", spec)
    return tuple(nets)


def is_excluded(ip: str, nets: tuple) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(a in n for n in nets if n.version == a.version)


def extract_caddy(entry: dict) -> Optional[dict]:
    """Normalise a Caddy JSON access-log entry into the flat request dict the profiler uses."""
    req = entry.get("request", {}) or {}
    host = (req.get("host") or "unknown").split(":")[0]
    uri = req.get("uri", "/") or "/"
    headers = req.get("headers", {}) or {}

    def _h(name):
        v = headers.get(name)
        if isinstance(v, list):
            return v[0] if v else ""
        return v or ""

    real_ip = _h("Cf-Connecting-Ip") or _h("X-Forwarded-For").split(",")[0].strip() or req.get("client_ip", req.get("remote_ip", ""))
    return {"ts": entry.get("ts", 0), "host": host, "path": uri.split("?")[0], "uri": uri, "method": req.get("method", "GET"),
            "status": entry.get("status", 0), "duration": entry.get("duration", 0), "size": entry.get("size", 0),
            "ip": real_ip, "user_agent": _h("User-Agent")}


def _entropy(values: list) -> float:
    """Shannon entropy of a discrete distribution."""
    if not values:
        return 0.0
    n = len(values)
    counts = Counter(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


_SENSITIVE_KW = [
    "admin", "wp-", "php", ".env", "config", "passwd", "shadow",
    "etc/", "proc/", "shell", "cmd", "exec", "eval", "setup",
    "xmlrpc", "cgi-bin", "phpmyadmin", "adminer", "backup",
]


def extract_features(requests: list[dict]) -> dict:
    """Extract 18 behavioral features from a sequence of requests for one IP."""
    if not requests:
        return {}

    reqs = sorted(requests, key=lambda r: r.get("ts", 0))
    timestamps = [r["ts"] for r in reqs if r["ts"]]
    paths = [r["path"] for r in reqs]
    methods = [r["method"] for r in reqs]
    statuses = [r["status"] for r in reqs]
    hosts = [r["host"] for r in reqs]
    uas = [r.get("user_agent", "") for r in reqs]
    sizes = [r.get("size", 0) for r in reqs]

    # Inter-request deltas
    deltas = [timestamps[i + 1] - timestamps[i]
              for i in range(len(timestamps) - 1)] if len(timestamps) > 1 else []

    # ── 1  Temporal entropy (hour-of-day randomness)
    hour_buckets = [int(ts) % 86400 // 3600 for ts in timestamps]
    temporal_entropy = _entropy(hour_buckets)

    # ── 2  Request velocity (req/min) — log-scaled to prevent dominating DNA vector
    duration_s = (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 1
    raw_velocity = len(reqs) / max(duration_s / 60, 0.0167)
    velocity_rpm = math.log1p(raw_velocity)  # log(1+x) compresses unbounded range

    # ── 3  Acceleration (is activity speeding up or slowing down?)
    #   Clamped to [-1, 1] to prevent dominating the 18-dim DNA vector
    if len(deltas) >= 4:
        mid = len(deltas) // 2
        first_avg = sum(deltas[:mid]) / mid
        second_avg = sum(deltas[mid:]) / (len(deltas) - mid)
        raw_accel = (first_avg - second_avg) / max(first_avg, 0.001)
        acceleration = max(-1.0, min(1.0, raw_accel))
    else:
        acceleration = 0.0

    # ── 4  Path vocabulary richness (unique / total)
    unique_paths = len(set(paths))
    vocab_richness = unique_paths / max(len(paths), 1)

    # ── 5  Method entropy
    method_entropy = _entropy(methods)

    # ── 6  Error rate (4xx + 5xx)
    error_rate = sum(1 for s in statuses if s >= 400) / max(len(statuses), 1)

    # ── 7,8,9  Inter-request timing stats
    if deltas:
        irt_mean = sum(deltas) / len(deltas)
        irt_std = (sum((d - irt_mean) ** 2 for d in deltas) / len(deltas)) ** 0.5
        irt_median = sorted(deltas)[len(deltas) // 2]
    else:
        irt_mean = irt_std = irt_median = 0.0

    # ── 10  Session duration
    session_s = max(duration_s, 0)

    # ── 11  Domain spread
    domain_spread = len(set(hosts))

    # ── 12  Auth attempt ratio
    auth_paths = [p for p in paths
                  if "auth" in p.lower() or "login" in p.lower() or "register" in p.lower()]
    auth_ratio = len(auth_paths) / max(len(paths), 1)

    # ── 13  Sensitive path ratio
    sensitive_hits = sum(
        1 for p in paths if any(kw in p.lower() for kw in _SENSITIVE_KW)
    )
    sensitive_ratio = sensitive_hits / max(len(paths), 1)

    # ── 14  Bigram repeat rate (sequential pattern repetition)
    if len(paths) >= 4:
        bigrams = [(paths[i], paths[i + 1]) for i in range(len(paths) - 1)]
        bigram_repeat = 1 - (len(set(bigrams)) / max(len(bigrams), 1))
    else:
        bigram_repeat = 0.0

    # ── 15  Hour concentration (what fraction of activity is in peak hour)
    if hour_buckets:
        peak_hour = Counter(hour_buckets).most_common(1)[0]
        hour_concentration = peak_hour[1] / len(hour_buckets)
        peak_hour_utc = peak_hour[0]
    else:
        hour_concentration = 0.0
        peak_hour_utc = 0

    # ── 16  User-agent consistency (1.0 = same UA every request)
    if uas:
        ua_consistency = Counter(uas).most_common(1)[0][1] / len(uas)
    else:
        ua_consistency = 0.0

    # ── 17  Avg path depth
    depths = [p.count("/") for p in paths]
    avg_depth = sum(depths) / max(len(depths), 1)

    # ── 18  Response size variance (normalised coefficient of variation)
    if len(sizes) > 1 and sum(sizes) > 0:
        size_mean = sum(sizes) / len(sizes)
        size_std = (sum((s - size_mean) ** 2 for s in sizes) / len(sizes)) ** 0.5
        size_cv = size_std / max(size_mean, 1)
    else:
        size_cv = 0.0

    return {
        "total_requests": len(reqs),
        "temporal_entropy": round(temporal_entropy, 4),
        "velocity_rpm": round(velocity_rpm, 4),
        "acceleration": round(acceleration, 4),
        "vocab_richness": round(vocab_richness, 4),
        "method_entropy": round(method_entropy, 4),
        "error_rate": round(error_rate, 4),
        "irt_mean_s": round(irt_mean, 4),
        "irt_std_s": round(irt_std, 4),
        "irt_median_s": round(irt_median, 4),
        "session_duration_s": round(session_s, 2),
        "domain_spread": domain_spread,
        "auth_ratio": round(auth_ratio, 4),
        "sensitive_ratio": round(sensitive_ratio, 4),
        "bigram_repeat": round(bigram_repeat, 4),
        "peak_hour_utc": peak_hour_utc,
        "hour_concentration": round(hour_concentration, 4),
        "ua_consistency": round(ua_consistency, 4),
        "avg_path_depth": round(avg_depth, 4),
        "size_cv": round(size_cv, 4),
        "method_distribution": dict(Counter(methods)),
        "status_distribution": dict(Counter(str(s) for s in statuses)),
        "unique_paths": unique_paths,
        "unique_user_agents": len(set(uas)),
    }


# ── DNA vector keys (the dimensions that form the behavioral fingerprint)
_DNA_KEYS = [
    "temporal_entropy", "velocity_rpm", "acceleration", "vocab_richness",
    "method_entropy", "error_rate", "irt_mean_s", "irt_std_s",
    "domain_spread", "auth_ratio", "sensitive_ratio", "bigram_repeat",
    "hour_concentration", "ua_consistency", "avg_path_depth", "size_cv",
    "irt_median_s", "unique_paths",
]


def _to_vector(features: dict) -> list[float]:
    """Convert features to a fixed 18-dimensional DNA vector."""
    return [float(features.get(k, 0)) for k in _DNA_KEYS]


def _cosine_sim(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = sum(x * x for x in a) ** 0.5
    mag_b = sum(x * x for x in b) ** 0.5
    if mag_a < 1e-12 or mag_b < 1e-12:
        return 0.0
    return dot / (mag_a * mag_b)


# ══════════════════════════════════════════════════════════════════════════════
#  2.  ATTACKER ARCHETYPE CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def classify_archetype(features: dict) -> dict:
    """Classify an IP into one of five attacker archetypes using weighted scoring."""
    scores = {
        "scanner": 0.0,
        "brute_forcer": 0.0,
        "researcher": 0.0,
        "bot_crawler": 0.0,
        "targeted_operator": 0.0,
    }

    vr = features.get("vocab_richness", 0)
    er = features.get("error_rate", 0)
    ar = features.get("auth_ratio", 0)
    sr = features.get("sensitive_ratio", 0)
    vel = features.get("velocity_rpm", 0)
    br = features.get("bigram_repeat", 0)
    ua_c = features.get("ua_consistency", 0)
    irt_s = features.get("irt_std_s", 999)
    te = features.get("temporal_entropy", 0)
    ds = features.get("domain_spread", 0)
    hc = features.get("hour_concentration", 0)

    # Scanner: high error rate + sensitive paths are strongest signals
    scores["scanner"] += sr * 4.0          # sensitive paths = primary signal
    scores["scanner"] += er * 3.5          # high errors = probing
    scores["scanner"] += vr * 2.0          # path diversity
    scores["scanner"] += (1 - ar) * 0.5    # not auth-focused

    # Brute-forcer: hammering auth endpoints repeatedly
    scores["brute_forcer"] += ar * 5.0     # auth-heavy is the #1 signal
    scores["brute_forcer"] += (1 - vr) * 2.0
    scores["brute_forcer"] += min(vel / 10, 1) * 2.0
    scores["brute_forcer"] += br * 2.0     # repetitive sequences

    # Researcher: clean browsing, low errors, varied paths, single consistent UA
    scores["researcher"] += (1 - er) * 3.0          # low errors
    scores["researcher"] += ua_c * 1.5
    scores["researcher"] += min(vr * 2.0, 2.0)      # explores many pages
    scores["researcher"] += (1 - sr) * 2.0           # avoids sensitive paths

    # Bot/crawler: metronomic timing, known UA patterns, systematic
    if irt_s < 2.0:
        scores["bot_crawler"] += 2.0       # reduced from 3.0
    scores["bot_crawler"] += ua_c * 1.5
    scores["bot_crawler"] += max(0, (1 - te / 4)) * 1.5
    scores["bot_crawler"] += (1 - sr) * 1.0  # bots don't probe sensitive paths

    # Targeted operator: focused on few paths, specific domain, low noise
    scores["targeted_operator"] += (1 - vr) * 1.5
    scores["targeted_operator"] += (1 - er) * 1.5
    scores["targeted_operator"] += hc * 2.0
    if ds <= 2:
        scores["targeted_operator"] += 1.5

    # Normalise
    total = sum(scores.values())
    if total > 0:
        scores = {k: round(v / total, 4) for k, v in scores.items()}

    primary = max(scores, key=lambda k: scores[k])
    return {"primary": primary, "confidence": scores[primary], "scores": scores}


# ══════════════════════════════════════════════════════════════════════════════
#  3.  KILL CHAIN STAGE MAPPING
# ══════════════════════════════════════════════════════════════════════════════

_KILL_CHAIN = {
    "reconnaissance": [
        "robots.txt", "sitemap", "/.well-known", "/favicon", "HEAD /",
        ".git/", "/.env", "/server-status", "/server-info", "OPTIONS /",
    ],
    "weaponization": [
        "wp-login", "wp-admin", "xmlrpc", "wp-content", "wp-includes",
        "phpmyadmin", "adminer", "phpinfo", "cgi-bin", "/vendor/",
    ],
    "delivery": [
        "shell", "upload", "filemanager", "eval(", "exec(",
        "cmd", "backdoor", "webshell", "c99", "r57",
    ],
    "exploitation": [
        "../", "..%2f", "%00", "select+", "union+", "<script",
        "onerror=", "onload=", "alert(", "document.cookie",
    ],
    "installation": [
        "POST /api", "PUT /", "PATCH /", "/config", "/setup",
        "/install", "/update", "crontab",
    ],
    "command_control": [
        "callback", "beacon", "heartbeat", "check-in", "poll",
        "connect", "/ws/", "tunnel",
    ],
    "exfiltration": [
        "/export", "/download", "/dump", "/backup", "/extract",
        "/data", "/db", "mysqldump",
    ],
}

_KC_VERBS = {
    "reconnaissance": "performing reconnaissance on",
    "weaponization": "probing for exploitable attack surfaces on",
    "delivery": "attempting payload delivery against",
    "exploitation": "attempting exploitation of",
    "installation": "attempting persistence/installation on",
    "command_control": "establishing C2 communication with",
    "exfiltration": "attempting data exfiltration from",
}


def map_kill_chain(requests: list[dict]) -> dict:
    """Map observed behaviour to kill chain stages with confidence scores."""
    stage_hits: dict[str, int] = defaultdict(int)
    total = len(requests)
    if total == 0:
        return {}

    for req in requests:
        line = f"{req['method']} {req.get('uri', req['path'])}".lower()
        for stage, patterns in _KILL_CHAIN.items():
            for pat in patterns:
                if pat.lower() in line:
                    stage_hits[stage] += 1
                    break  # one match per stage per request

    return {
        stage: {
            "hits": count,
            "confidence": round(min(count / max(total * 0.1, 1), 1.0), 4),
        }
        for stage, count in sorted(stage_hits.items(), key=lambda x: -x[1])
    }


# ══════════════════════════════════════════════════════════════════════════════
#  4.  MARKOV CHAIN PREDICTION
# ══════════════════════════════════════════════════════════════════════════════

_PATH_CATS = {
    "root":   ["/", "/index"],
    "auth":   ["/login", "/signup", "/register", "/auth", "/api/auth"],
    "admin":  ["/admin", "/administrator", "/manage", "/api/admin"],
    "api":    ["/api/", "/graphql", "/rest"],
    "cms":    ["/wp-", "/wordpress", "/joomla", "/drupal"],
    "config": ["/.env", "/.git", "/config", "/.htaccess", "/web.config"],
    "shell":  ["/shell", "/cmd", "/exec", "/eval", "/backdoor"],
    "static": [".css", ".js", ".png", ".jpg", ".ico", ".svg", ".woff"],
    "scan":   ["/phpmy", "/phpmyadmin", "/adminer", "/server-status"],
}


def _categorize_path(path: str) -> str:
    p = path.lower()
    for cat, patterns in _PATH_CATS.items():
        if any(pat in p for pat in patterns):
            return cat
    return "other"


def build_markov(requests: list[dict]) -> dict:
    """Build a Markov transition matrix and predict next action."""
    if len(requests) < 2:
        return {"current_state": "unknown", "transitions": {}, "predictions": []}

    cats = [_categorize_path(r["path"]) for r in requests]

    # Transition counts
    trans: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for i in range(len(cats) - 1):
        trans[cats[i]][cats[i + 1]] += 1

    # To probabilities
    probs = {}
    for state, nexts in trans.items():
        total = sum(nexts.values())
        probs[state] = {
            k: round(v / total, 4)
            for k, v in sorted(nexts.items(), key=lambda x: -x[1])
        }

    # Predictions from last observed state
    last = cats[-1]
    preds = []
    if last in probs:
        for nxt, prob in list(probs[last].items())[:5]:
            preds.append({"from": last, "to": nxt, "probability": prob})

    return {"current_state": last, "transitions": probs, "predictions": preds}


# ══════════════════════════════════════════════════════════════════════════════
#  5.  BEHAVIORAL CLUSTERING  (find the same human behind different IPs)
# ══════════════════════════════════════════════════════════════════════════════

def cluster_by_behaviour(profiles: dict, threshold: float = 0.85) -> list[dict]:
    """Cluster IPs whose DNA vectors are ALL pairwise cosine-similar >= threshold.

    Complete linkage, not single linkage: the old union-find chained pairs
    (A~B, B~C => {A,B,C} even when A and C are dissimilar), so clusters were
    labelled "likely same operator" at an average similarity of 67-74% under a
    stated 0.85 threshold (audit 2026-10-18). Edges are merged strongest-first
    and two groups only join when every cross pair clears the threshold, so
    each reported cluster's MIN (and therefore average) similarity >= threshold.
    Excluded IPs are filtered by the caller before profiling (is_excluded)."""
    # Pure Python (no numpy in the sandbox image). O(n^2) pairs: cap at the MAX_CLUSTER_IPS most active IPs.
    ips = sorted(profiles.keys(), key=lambda ip: -profiles[ip]["features"].get("total_requests", 0))[:MAX_CLUSTER_IPS]
    n = len(ips)
    if n < 2:
        return []
    raw = [_to_vector(profiles[ip]["features"]) for ip in ips]
    dims = len(raw[0])
    # Z-score normalise so high-magnitude features (velocity, IRT) don't dominate cosine
    means = [sum(v[d] for v in raw) / n for d in range(dims)]
    stds = [math.sqrt(sum((v[d] - means[d]) ** 2 for v in raw) / n) or 1.0 for d in range(dims)]
    unit = []
    for v in raw:
        z = [(v[d] - means[d]) / stds[d] for d in range(dims)]
        nrm = math.sqrt(sum(x * x for x in z))
        unit.append([x / nrm for x in z] if nrm >= 1e-12 else None)
    sim = [[0.0] * n for _ in range(n)]
    edges = []
    for i in range(n):
        sim[i][i] = 1.0
        ui = unit[i]
        if ui is None:
            continue
        for j in range(i + 1, n):
            uj = unit[j]
            if uj is None:
                continue
            sv = sum(a * b for a, b in zip(ui, uj))
            sim[i][j] = sim[j][i] = sv
            if sv >= threshold:
                edges.append((sv, i, j))
    if not edges:
        return []
    edges.sort(key=lambda e: -e[0])

    # Complete-linkage merge: two groups join only when EVERY cross pair clears the threshold
    cid_of = list(range(n))
    members_of: dict[int, list[int]] = {i: [i] for i in range(n)}
    for _sv, a, b in edges:
        ca, cb = cid_of[a], cid_of[b]
        if ca == cb:
            continue
        ma, mb = members_of[ca], members_of[cb]
        if min(sim[x][y] for x in ma for y in mb) < threshold:
            continue
        if len(ma) < len(mb):
            ca, cb, ma, mb = cb, ca, mb, ma
        ma.extend(mb)
        for m in mb:
            cid_of[m] = ca
        del members_of[cb]

    clusters = []
    for idxs in members_of.values():
        if len(idxs) < 2:
            continue
        members = [ips[i] for i in idxs]
        archetypes = [profiles[ip]["archetype"]["primary"] for ip in members]
        shared = Counter(archetypes).most_common(1)[0][0]
        pairs = [sim[idxs[x]][idxs[y]] for x in range(len(idxs)) for y in range(x + 1, len(idxs))]
        avg_sim = sum(pairs) / len(pairs)
        min_sim = min(pairs)
        cid = hashlib.md5("|".join(sorted(members)).encode()).hexdigest()[:8]
        clusters.append({
            "cluster_id": cid,
            "members": sorted(members),
            "size": len(members),
            "avg_similarity": round(avg_sim, 4),
            "min_similarity": round(min_sim, 4),
            "threshold": threshold,
            "linkage": "complete",
            "shared_archetype": shared,
            "assessment": (
                f"Similar behaviour (possible same operator) — {len(members)} IPs "
                f"with correlated {shared} behaviour (avg similarity {avg_sim:.0%}, "
                f"min {min_sim:.0%}, every pair ≥ {threshold:.0%})"
            ),
        })

    return sorted(clusters, key=lambda c: (-c["size"], -c["avg_similarity"]))


# ══════════════════════════════════════════════════════════════════════════════
#  6.  THREAT NARRATIVE GENERATION
# ══════════════════════════════════════════════════════════════════════════════

_ARCH_DESC = {
    "scanner": "automated vulnerability scanner",
    "brute_forcer": "credential brute-force operator",
    "researcher": "security researcher or legitimate user",
    "bot_crawler": "automated bot or web crawler",
    "targeted_operator": "targeted threat operator",
}


def generate_narrative(ip: str, profile: dict) -> str:
    """Auto-generate a human-readable threat narrative for one IP."""
    f = profile["features"]
    arch = profile["archetype"]
    kc = profile["kill_chain"]
    markov = profile["markov"]

    desc = _ARCH_DESC.get(arch["primary"], "unknown operator")
    conf = int(arch["confidence"] * 100)
    lines = [f"**{ip}** — classified as {desc} ({conf}% confidence)."]

    # Ninja Cloud attribution leads the narrative when the IP is known-malicious.
    ti = profile.get("threat_intel")
    if profile.get("threat_intel_unavailable"):
        lines.insert(
            0,
            "⚠ ATTRIBUTION UNAVAILABLE — the Ninja Cloud threat graph could not "
            "be queried, so this IP has **not** been checked against known "
            "malicious infrastructure.",
        )
    elif ti and ti.get("known_malicious"):
        fam = ti.get("label") or "known malicious infrastructure"
        seen = (ti.get("last_seen") or "")[:10]
        seen_str = f", last seen {seen} in threat intel" if seen else ""
        lines.insert(
            0,
            f"⚠ KNOWN MALICIOUS — Ninja Cloud attributes this IP to "
            f"**{fam}**{seen_str}.",
        )

    # Activity window
    total = f.get("total_requests", 0)
    dur = f.get("session_duration_s", 0)
    if dur > 3600:
        dur_str = f"{dur / 3600:.1f}h"
    elif dur > 60:
        dur_str = f"{dur / 60:.1f}m"
    else:
        dur_str = f"{dur:.0f}s"
    lines.append(
        f"Observed {total} requests over {dur_str} "
        f"({f.get('velocity_rpm', 0):.1f} req/min)."
    )

    # Kill chain
    if kc:
        top_stage = next(iter(kc))
        verb = _KC_VERBS.get(top_stage, "interacting with")
        lines.append(f"Primary activity: {verb} the infrastructure ({top_stage}).")

    # Domain spread
    ds = f.get("domain_spread", 0)
    if ds > 3:
        lines.append(
            f"Active across {ds} domains — broad ecosystem reconnaissance."
        )
    elif ds > 1:
        lines.append(f"Targeting {ds} domains.")

    # Behavioural flags
    if f.get("error_rate", 0) > 0.5:
        lines.append(
            f"High error rate ({f['error_rate'] * 100:.0f}%) — "
            "automated probing or misconfigured tooling."
        )
    if f.get("sensitive_ratio", 0) > 0.3:
        lines.append(
            f"Targeting sensitive paths ({f['sensitive_ratio'] * 100:.0f}% of requests) "
            "— indicates malicious intent."
        )
    if f.get("ua_consistency", 0) < 0.5 and total > 10:
        lines.append("Rotating user-agents detected — possible evasion technique.")
    if f.get("acceleration", 0) > 0.3:
        lines.append("Activity accelerating — escalating engagement.")
    elif f.get("acceleration", 0) < -0.3:
        lines.append("Activity decelerating — may have achieved objective or abandoned.")
    if f.get("bigram_repeat", 0) > 0.4:
        lines.append("Highly repetitive request sequences — scripted automation.")
    if f.get("auth_ratio", 0) > 0.5:
        lines.append(
            f"Auth-heavy traffic ({f['auth_ratio'] * 100:.0f}% auth endpoints) "
            "— credential-focused attack."
        )

    # Prediction
    preds = markov.get("predictions", [])
    if preds:
        top = preds[0]
        lines.append(
            f"Next predicted action: **{top['to']}** "
            f"(probability {top['probability'] * 100:.0f}%)."
        )

    return " ".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  7.  NINJA CLOUD THREAT-INTEL CORRELATION
#
#  The behavioural DNA above is computed entirely on-box by the local scanner —
#  raw logs never leave the customer's edge. But naming the adversary (turning
#  "scanner, 41% confidence" into "Mirai botnet C2, last seen yesterday")
#  requires the global threat graph. The scanner batches only its observed IPs
#  and asks Ninja Cloud (the Signal threat-intelligence graph, 500k+ indicators
#  from abuse.ch / OTX / CISA KEV / community feeds) for attribution.
# ══════════════════════════════════════════════════════════════════════════════



# ══════════════════════════════════════════════════════════════════════════════
#  7.  THE PIPELINE (entries in, profiles/clusters/narratives out)
# ══════════════════════════════════════════════════════════════════════════════

def analyse(entries: list[dict], min_requests: int = 3, exclude: Iterable[str] = (),
            attribution: Optional[Callable[[list[str]], dict]] = None, narratives_top: int = 25) -> dict:
    """Full Adversary DNA over a list of flat request dicts (oldest first is best; sorted here anyway)."""
    nets = exclusion_nets(exclude)
    entries = [e for e in entries if e and e.get("ip")]
    n_before = len(entries)
    entries = [e for e in entries if not is_excluded(e["ip"], nets)]
    entries.sort(key=lambda r: r.get("ts") or 0)
    excluded = n_before - len(entries)
    if not entries:
        return {"status": "no_data", "profiles": {}, "clusters": [], "narratives": [],
                "summary": {"total_ips": 0, "profiled": 0, "below_threshold": 0, "clusters_found": 0, "archetypes": {},
                            "dna_dimensions": len(_DNA_KEYS), "excluded_requests": excluded}}
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        by_ip[e["ip"]].append(e)
    profiles: dict[str, dict] = {}
    for ip, reqs in by_ip.items():
        if len(reqs) < min_requests:
            continue
        feats = extract_features(reqs)
        vec = _to_vector(feats)
        profiles[ip] = {"dna_hash": hashlib.sha256("|".join(f"{v:.4f}" for v in vec).encode()).hexdigest()[:16],
                        "features": feats, "dna_vector": [round(v, 6) for v in vec], "archetype": classify_archetype(feats),
                        "kill_chain": map_kill_chain(reqs), "markov": build_markov(reqs)}
    intel: dict = {}
    attribution_error = None
    if attribution is not None:
        try:
            intel = attribution(list(profiles.keys())) or {}
        except Exception as exc:  # noqa: BLE001
            attribution_error = f"{type(exc).__name__}: {exc}"
    for ip, p in profiles.items():
        p["threat_intel"] = intel.get(ip)
    clusters = cluster_by_behaviour(profiles)
    for c in clusters:
        flagged = [m for m in c.get("members", []) if intel.get(m)]
        if flagged:
            c["known_malicious"] = flagged
    sorted_ips = sorted(profiles, key=lambda ip: profiles[ip]["features"]["total_requests"], reverse=True)
    attributed = [ip for ip in sorted_ips if profiles[ip].get("threat_intel")]
    narratives = []
    for ip in list(dict.fromkeys(attributed + sorted_ips[:narratives_top])):
        p = profiles[ip]
        narratives.append({"ip": ip, "dna_hash": p["dna_hash"], "archetype": p["archetype"]["primary"], "confidence": p["archetype"]["confidence"],
                           "total_requests": p["features"]["total_requests"], "kill_chain_stages": list(p["kill_chain"].keys()),
                           "next_prediction": (p["markov"]["predictions"][0] if p["markov"].get("predictions") else None),
                           "threat_intel": p.get("threat_intel"), "narrative": generate_narrative(ip, p)})
    arch_dist = Counter(p["archetype"]["primary"] for p in profiles.values())
    return {"status": "ok", "total_entries": len(entries), "profiles": profiles, "clusters": clusters, "narratives": narratives,
            "attribution": {"available": attribution is not None, "error": attribution_error, "attributed": len(intel) if attribution is not None else None},
            "summary": {"total_ips": len(by_ip), "profiled": len(profiles), "below_threshold": len(by_ip) - len(profiles),
                        "clusters_found": len(clusters), "archetypes": dict(arch_dist), "dna_dimensions": len(_DNA_KEYS),
                        "excluded_requests": excluded}}


def profile_ip(entries: list[dict], ip: str) -> dict:
    reqs = sorted([e for e in entries if e.get("ip") == ip], key=lambda r: r.get("ts") or 0)
    if not reqs:
        return {"status": "not_found", "ip": ip}
    feats = extract_features(reqs)
    p = {"features": feats, "archetype": classify_archetype(feats), "kill_chain": map_kill_chain(reqs), "markov": build_markov(reqs),
         "dna_vector": [round(v, 6) for v in _to_vector(feats)]}
    p["dna_hash"] = hashlib.sha256("|".join(f"{v:.4f}" for v in p["dna_vector"]).encode()).hexdigest()[:16]
    p["narrative"] = generate_narrative(ip, p)
    p["requests"] = [{"ts": r.get("ts"), "method": r.get("method"), "host": r.get("host"), "uri": (r.get("uri") or "")[:200], "status": r.get("status"), "ua": (r.get("user_agent") or "")[:120]} for r in reqs[-200:]]
    return {"status": "ok", "ip": ip, **p}


def compare(entries: list[dict], ip_a: str, ip_b: str) -> dict:
    a, b = profile_ip(entries, ip_a), profile_ip(entries, ip_b)
    if a.get("status") != "ok" or b.get("status") != "ok":
        return {"status": "not_found"}
    sim = _cosine_sim(a["dna_vector"], b["dna_vector"])
    return {"status": "ok", "similarity": round(sim, 4), "same_operator_likely": sim > 0.85,
            "a": {"ip": ip_a, "archetype": a["archetype"]["primary"]}, "b": {"ip": ip_b, "archetype": b["archetype"]["primary"]}}
