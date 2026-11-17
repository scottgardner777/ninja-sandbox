"""The Raz0r Sensor: the front-door feeder, generalised.

Ninja's own edge runs this against Caddy on Box 1 (ninja-funk/agents/perimeter_push.py). Here it reads any
reverse proxy's access log (Caddy JSON, nginx/Apache combined, Traefik JSON), on-host from a file or off-host
over syslog, or sits inline as a tiny logging reverse proxy; folds everything into per-IP aggregates (requests
per site, status classes, probe families with CVE tags, UA family), extracts the dropper URLs attackers try to
make your server fetch (the "load the malware in situ" path), and hands the request stream to Adversary DNA.
Raw log lines never leave the box. Telemetry (opt-in) is the per-IP aggregate rows, nothing else.
"""
