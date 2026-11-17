"""Ninja Sandbox: a free malware detonation range + the Raz0r edge sensor + Adversary DNA.

Layout
  sandbox.config    paths, settings.json (mode / BYOK / telemetry), environment knobs
  sandbox.triage    static triage of a dropped file: kind, arch, strings, IOCs, entropy, packer, ELF structure
  sandbox.elf       pure-python ELF parser (header, segments, sections, NEEDED libs, dynamic symbols)
  sandbox.cell      the detonation cell: sinkhole + namespace holder + zero-capability runner, 60 s, no egress
  sandbox.reverse   the deep-insight report: static + dynamic (syscall timeline, process tree, files, network, C2, ATT&CK)
  sandbox.dna       Adversary DNA: 18-dim behavioural fingerprint per IP, archetype, kill chain, Markov, clustering
  sandbox.sensor    the Raz0r Sensor: Caddy/nginx/Apache/Traefik logs -> per-IP aggregates, probe families,
                    dropper URLs seen in the attack traffic -> samples land in the sandbox in situ
  sandbox.explain   BYOK write-up (Anthropic or an OpenAI-compatible local server); deterministic report otherwise
  sandbox.api       FastAPI: /api/sandbox/* + the single-page UI
"""
__version__ = "0.1.0"
