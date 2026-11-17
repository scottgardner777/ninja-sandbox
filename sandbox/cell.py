"""The detonation cell, as a library.

Ported from the skunkbox honeynet's cell/detonate.py (2026-11-15) and made standalone: paths come from
sandbox.config, the sinkhole script and runner images are built from ./cell, and the host path of the data
directory is translated for bind mounts when this code itself runs inside a container (Docker socket).

How one detonation works (no VM, no KVM needed: isolation is Docker + an internal network + capabilities):
  1. `sandbox-cell` is an INTERNAL Docker network (no gateway to the outside world).
  2. the sinkhole container (NET_ADMIN, 10.66.0.2) joins it: every DNS answer points at itself, every TCP/UDP
     destination is REDIRECTed to itself, and it logs the ORIGINAL destination + the first bytes + a pcap.
  3. a namespace HOLDER container (NET_ADMIN, never touches the sample) joins the network and points the
     default route at the sinkhole, so a connect() to any internet address lands on the sinkhole.
  4. the RUNNER joins the holder's network namespace with --cap-drop ALL, no-new-privileges, read-only root,
     tmpfs /tmp, 64 pids, 256 MiB, 1 CPU, default seccomp/AppArmor, and runs the sample under strace
     (native) or QEMU_STRACE (foreign arch via binfmt) for TIMEOUT seconds, then SIGKILL.
  5. everything is torn down; the host never executes the sample.

Hard requirement on the box: Docker. For non-x86-64 samples: `docker run --privileged --rm tonistiigi/binfmt --install all`.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, Optional

from . import config

NET = os.environ.get("SANDBOX_CELL_NET", "sandbox-cell")
SUBNET = os.environ.get("SANDBOX_CELL_SUBNET", "10.66.0.0/24")
SINK_IP = os.environ.get("SANDBOX_CELL_SINK_IP", "10.66.0.2")
SINK_NAME = "sandbox-sinkhole"
IMAGES = {"arm": ("ninja-sandbox-cell:armv7", "linux/arm/v7"), "aarch64": ("ninja-sandbox-cell:arm64", "linux/arm64"),
          "x86": ("ninja-sandbox-cell:386", "linux/386"), "x86-64": ("ninja-sandbox-cell:amd64", "linux/amd64"),
          "mips": ("ninja-sandbox-cell:mips", None), "ppc": None, "sh4": None, "sparc": None, "m68k": None, "riscv": None}
NATIVE = {"x86-64"}
SINK_IMAGE = "ninja-sandbox-cell:sinkhole"
HERE = os.path.dirname(os.path.abspath(__file__))
SINK_SCRIPT = os.path.join(HERE, "sinkhole.py")
HOST_SINK_SCRIPT = os.environ.get("SANDBOX_HOST_SINKHOLE", "")   # host path of sinkhole.py when running in a container
_busy = threading.Lock()


def sh(cmd, timeout=120, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def host_path(p: str) -> str:
    """Translate a path under DATA into the host's view of it (for -v bind mounts via the Docker socket)."""
    p = os.path.abspath(p)
    if config.HOST_DATA != config.DATA and p.startswith(config.DATA):
        return config.HOST_DATA + p[len(config.DATA):]
    return p


def docker_ok() -> Dict[str, Any]:
    r = sh(["docker", "version", "--format", "{{.Server.Version}}"], timeout=20)
    imgs = sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=30).stdout.split() if r.returncode == 0 else []
    have = {k: (v[0] in imgs) for k, v in IMAGES.items() if v}
    binfmt = False
    try:
        binfmt = any(n.startswith("qemu-") for n in os.listdir("/proc/sys/fs/binfmt_misc"))
    except OSError:
        pass
    return {"docker": r.returncode == 0, "server": r.stdout.strip() if r.returncode == 0 else r.stderr.strip()[-200:],
            "images": have, "sinkhole_image": SINK_IMAGE in imgs, "binfmt_foreign_arch": binfmt,
            "ready": r.returncode == 0 and have.get("x86-64", False) and SINK_IMAGE in imgs}


def ensure_net() -> None:
    if NET not in sh(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split():
        sh(["docker", "network", "create", "--internal", "--subnet", SUBNET, NET])


def start_sinkhole(outdir: str) -> str:
    sh(["docker", "rm", "-f", SINK_NAME])
    script = HOST_SINK_SCRIPT or SINK_SCRIPT
    r = sh(["docker", "run", "-d", "--name", SINK_NAME, "--network", NET, "--ip", SINK_IP, "--cap-add", "NET_ADMIN",
            "--cap-add", "NET_RAW", "--memory", "128m", "--pids-limit", "64", "-e", f"SINK_IP={SINK_IP}",
            "-v", f"{host_path(outdir)}:/out", "-v", f"{script}:/sinkhole.py:ro", SINK_IMAGE, "python3", "/sinkhole.py"])
    if r.returncode:
        raise RuntimeError("sinkhole failed: " + r.stderr[-300:])
    time.sleep(1.5)
    return SINK_IP


def run_sample(sample_path: str, arch: str, outdir: str, timeout: int, label: str) -> Dict[str, Any]:
    img = IMAGES.get(arch)
    if not img or not img[0]:
        return {"status": "unsupported_arch", "arch": arch}
    image, platform = img
    if image not in sh(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"]).stdout.split():
        return {"status": "no_runner_image", "image": image, "hint": "run cell/build.sh"}
    if arch not in NATIVE and not docker_ok()["binfmt_foreign_arch"]:
        return {"status": "no_binfmt", "arch": arch, "hint": "docker run --privileged --rm tonistiigi/binfmt --install all"}
    sdir = tempfile.mkdtemp(prefix="cell-", dir=outdir)
    shutil.copy(sample_path, os.path.join(sdir, "sample"))
    os.chmod(os.path.join(sdir, "sample"), 0o555)
    name, holder = f"sandbox-run-{label}", f"sandbox-ns-{label}"
    sh(["docker", "rm", "-f", name]); sh(["docker", "rm", "-f", holder])
    rh = sh(["docker", "run", "-d", "--name", holder, "--network", NET, "--dns", SINK_IP, "--cap-add", "NET_ADMIN",
             "--memory", "32m", "--pids-limit", "8", IMAGES["x86-64"][0], "sh", "-c",
             f"ip route replace default via {SINK_IP} && exec sleep {timeout + 300}"])
    if rh.returncode:
        shutil.rmtree(sdir, ignore_errors=True)
        return {"status": "holder_failed", "err": rh.stderr[-300:]}
    time.sleep(0.8)
    cmd = ["docker", "run", "--name", name, "--network", f"container:{holder}", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp:exec,size=64m", "--pids-limit", "64",
           "--memory", "256m", "--cpus", "1", "-v", f"{host_path(sdir)}:/s:ro", "-v", f"{host_path(outdir)}:/out", "--stop-timeout", "2"]
    if platform:
        cmd += ["--platform", platform]
    if arch in NATIVE:
        inner = (f"cp /s/sample /tmp/x && chmod +x /tmp/x && cd /tmp && (timeout -s KILL {timeout} strace -f -tt -s 200 "
                 f"-e trace=network,process,file,desc,signal,ipc -o /out/strace.txt /tmp/x > /out/stdout.txt 2>&1; echo $? > /out/exit.txt); "
                 f"ls -la /tmp > /out/tmp_after.txt 2>&1; true")
    else:
        cmd += ["-e", "QEMU_STRACE=1"]
        inner = (f"cp /s/sample /tmp/x && chmod +x /tmp/x && cd /tmp && (timeout -s KILL {timeout} /tmp/x > /out/stdout.txt 2> /out/strace.txt; "
                 f"echo $? > /out/exit.txt); ls -la /tmp > /out/tmp_after.txt 2>&1; true")
    cmd += [image, "sh", "-c", inner]
    t0 = time.time()
    try:
        r = sh(cmd, timeout=timeout + 60)
        rc, err = r.returncode, r.stderr[-300:]
    except subprocess.TimeoutExpired:
        rc, err = -1, "docker run exceeded the hard timeout"
    sh(["docker", "rm", "-f", name]); sh(["docker", "rm", "-f", holder])
    shutil.rmtree(sdir, ignore_errors=True)
    return {"status": "ran", "seconds": round(time.time() - t0, 1), "docker_rc": rc, "docker_err": err,
            "tracer": "strace" if arch in NATIVE else "qemu-strace", "image": image}


def detonate(sha: str, meta: Dict[str, Any], timeout: Optional[int] = None) -> Dict[str, Any]:
    """Run one sample once. Returns the detonation record (also written to DETONATIONS/<sha>.json).

    Serialised: one cell at a time per box (the sinkhole name and IP are fixed)."""
    from . import reverse
    config.ensure_dirs()
    timeout = int(timeout or config.load_settings()["cell"]["timeout_s"])
    sample_path = os.path.join(config.SAMPLES, sha)
    if not os.path.isfile(sample_path):
        return {"sha256": sha, "run": {"status": "no_sample"}}
    with _busy:
        outdir = tempfile.mkdtemp(prefix="cellout-", dir=config.DETONATIONS)
        os.chmod(outdir, 0o777)
        rec: Dict[str, Any] = {"sha256": sha, "arch": meta.get("arch"), "bits": meta.get("bits"), "size": meta.get("size"),
                               "kind": meta.get("kind"), "detonated": config.now_iso(), "timeout_s": timeout}
        try:
            ensure_net()
            sink = start_sinkhole(outdir)
            if meta.get("kind") != "elf":
                rec["run"] = {"status": "not_elf", "kind": meta.get("kind"), "note": "the cell runs Linux ELF; scripts are read, not run"}
            else:
                rec["run"] = run_sample(sample_path, meta.get("arch", ""), outdir, timeout, sha[:12])
        except Exception as e:  # noqa: BLE001
            rec["run"] = {"status": "cell_error", "err": f"{type(e).__name__}: {e}"[:300]}
            sink = SINK_IP
        time.sleep(0.5)   # let tcpdump flush
        sh(["docker", "rm", "-f", SINK_NAME])
        if rec["run"].get("status") == "ran":
            rec.update(reverse.analyse_dynamic(outdir, sink))
            for src, dst in (("strace.txt", f"{sha}.strace.txt"), ("sinkhole.jsonl", f"{sha}.sinkhole.jsonl"),
                             ("capture.pcap", f"{sha}.pcap"), ("stdout.txt", f"{sha}.stdout.txt"), ("tmp_after.txt", f"{sha}.tmp_after.txt")):
                try:
                    shutil.copy(os.path.join(outdir, src), os.path.join(config.DETONATIONS, dst))
                except FileNotFoundError:
                    pass
            try:
                rec["exit"] = open(os.path.join(outdir, "exit.txt")).read().strip()
            except FileNotFoundError:
                pass
            rec["artifacts"] = {k: os.path.exists(os.path.join(config.DETONATIONS, f"{sha}.{k}")) for k in ("strace.txt", "sinkhole.jsonl", "pcap", "stdout.txt")}
        shutil.rmtree(outdir, ignore_errors=True)
        with open(os.path.join(config.DETONATIONS, f"{sha}.json"), "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=1)
    config.event("detonated", sha256=sha, status=rec["run"].get("status"), verdict=rec.get("verdict"), seconds=rec["run"].get("seconds"))
    return rec


def load_detonation(sha: str) -> Optional[Dict[str, Any]]:
    try:
        with open(os.path.join(config.DETONATIONS, f"{sha}.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def build_images(cell_dir: str) -> Dict[str, Any]:
    """`cell/build.sh` from Python (the Settings tab's "build the cell" button)."""
    r = sh(["bash", os.path.join(cell_dir, "build.sh")], timeout=1800, cwd=cell_dir)
    return {"rc": r.returncode, "out": (r.stdout + r.stderr)[-3000:]}
