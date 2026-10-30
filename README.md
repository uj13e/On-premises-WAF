# Reverse-Proxy WAF

[日本語](README.ja.md) | English

A reverse-proxy **Web Application Firewall** written in pure Python (standard library only), with a built-in management dashboard and a live attack map.

It sits in front of a web application, inspects every request, and blocks (or just logs) XSS, SQL injection, path traversal, command injection and other attacks before they reach the backend.

```
Browser ──► [ WAF :8080 ] ── inspect ──► your backend app
                │   └─► logs ──► [ Dashboard :8090 ]  (same process, attack map)
                ├─ dangerous → 403 (block mode) / log only (detect mode)
                └─ adds security headers (CSP etc.) to responses
```

> **The backend application is not included.**
> This repository contains only the WAF and its dashboard. The sample config points at `https://127.0.0.1:5000`, where the author ran a small stored-XSS demo bulletin board for testing. That app is **not** part of this repo, so you need to bring your own backend (see [Quick start](#quick-start)).

> For education and authorized testing only. Do not use it against systems you do not own or have permission to test.

## Features

- **Request inspection**: URL, query, headers, body and cookies are decoded in multiple stages and checked against about 100 rules in 15 categories (XSS, SQLi, traversal, command injection, SSRF, XXE, SSTI, NoSQLi, LDAP, CRLF, open redirect, upload, scanners, deserialization, and more). Each rule can be set to block, detect-only, or off.
- **Response inspection**: sanitizes or blocks stored-XSS payloads in the HTML the backend returns.
- **DoS and abusive connection handling**: rate limiting, connection limits, Slowloris / Slow POST deadlines, body size limit, request smuggling checks, and automatic bans for repeat offenders.
- **IP and country control**: manual bans, allowlists, exempt IPs, country allow/block lists (offline GeoIP supported).
- **Multiple backends at once**: route by dedicated port, host name or path, each with its own mode, rules, IP policy and health check.
- **Dashboard**: home, traffic charts, real-time and aggregated attack maps, event log with a Burp-style detail view, status log, IP management and rule management.
- **Attack alerts**: a warning banner and an "EMERGENCY" hexagon background when an attack is detected.
- **Users, organizations and roles**: admin / analyst / user / key officer, an organization tree with scopes, masked logs, and a ticket workflow.
- **Log handling**: per-backend daily logs, retention, export, and optional encryption of log details with per-organization public keys.
- **Integrations**: webhook notifications, e-mail notifications for tickets, and operation behind another reverse proxy such as nginx.

## Requirements

- Python 3.8 or later (a static check finds no syntax or standard-library use newer than that; tested on 3.13 and 3.14)
- No third-party packages are required.
- Optional: `cryptography` (generating the self-signed certificate and log-detail encryption; the `openssl` CLI is used as a fallback for the certificate) and `python-geoip-geolite2` (offline country lookup).

## Quick start

1. Start any web app as the backend. For a quick try, plain HTTP is fine:

   ```bash
   mkdir site && cd site
   echo "<h1>hello backend</h1>" > index.html
   python3 -m http.server 5000
   ```

2. In another terminal, start the WAF from the repository root and point it at that backend:

   ```bash
   python3 waf.py --backend http://127.0.0.1:5000 --no-listen-tls
   ```

3. Open the WAF address instead of the backend address:

   - `http://127.0.0.1:8080/` is passed through to the backend.
   - `http://127.0.0.1:8080/?q=<script>alert(1)</script>` is blocked with `403`.

4. Open the dashboard at `https://127.0.0.1:8090`. The certificate is self-signed, so the browser will warn you once.

Without `--no-listen-tls`, the WAF listens on HTTPS and generates a self-signed certificate if `data/waf_cert.pem` and `data/waf_key.pem` are missing.

To use the shipped sample config as it is (four sample backends on ports 8081–8084, all forwarding to `https://127.0.0.1:5000`), run your own HTTPS app on port 5000, or edit the backends in `config/waf_config.json` or in the dashboard under Settings → Backends.

### Useful options

```bash
python3 waf.py --mode detect                       # log only, do not block (good for first trials)
python3 waf.py --mode block                        # block mode
python3 waf.py --site shop=8081=https://192.168.0.10:5000 --site blog=8082=http://192.168.0.20:3000
python3 waf.py --path-route /shop=https://192.168.0.10:5000 --path-route /blog=http://192.168.0.20:3000
python3 waf.py --allow-country JP --block-ip 203.0.113.0/24
python3 waf.py --help                              # everything else
```

## Ports

| Port | What | Notes |
|---|---|---|
| 8080 | WAF | HTTPS by default |
| 8081–8084 | Per-backend WAF ports | From the sample config, one per sample backend |
| 8090 | Dashboard | HTTPS, login required |
| 127.0.0.1:8099 | Rule management tool | Start with `start_rules_tool.bat` |

## Dashboard login

The sample config defines users such as `admin`, `soc` and `ko` under `dashboard.users`, but their passwords are not published. Set your own by replacing `password_hash`. From the repository root:

```bash
python3 -c "import sys; sys.path.insert(0,'src'); import waf_extras as w; print(w.hash_password('YOUR_PASSWORD'))"
```

Paste the output into the `password_hash` of the user in `config/waf_config.json`. If you empty `dashboard.users`, the dashboard falls back to a single shared password (`dashboard.password`).

## About the sample keys and config

- `秘密鍵/` (Japanese for "private keys") and `data/waf_key.pem` contain **demo keys** that are published on purpose so the log-encryption workflow can be tried out. Anyone can read them. Never reuse them for real data, and generate your own keys before any real use.
- `enc_demo_keys` is `true` in the sample config. Turn it off for real use.
- The dashboard listens on `0.0.0.0` in the sample config. Change `dashboard.host` to `127.0.0.1` if you do not want it reachable from the network.
- `log_pass_body` is `true`, which also records bodies of requests that passed. Be careful with credentials.

## Tests

```bash
python3 tests/test_waf.py      # core features (144 checks)
python3 tests/test_merged.py   # defenses, dashboard, permissions, rule settings (402 checks)
```

Both scripts start their own dummy backend, so they do not need the real application.

## Layout

```
waf.py                  main program: proxy + dashboard in one process
start_rules_tool.bat    starts the rule management tool (Windows)
src/                    modules and the bundled world map
config/                 waf_config.json (and custom_rules.json when created)
data/                   runtime data (logs, tickets, audit log, certificates)
tests/                  tests
docs/README.md          detailed documentation (Japanese)
```

The detailed documentation, covering every setting, the dashboard screens, log encryption and the key officer workflow, is in [docs/README.md](docs/README.md) (Japanese).

## Limitations

A signature-based WAF is one layer of defense, not a fix for vulnerable code. It cannot stop every unknown or heavily obfuscated attack, so keep fixing the application itself (output escaping, sanitizing, CSP).

## License

[MIT](LICENSE)
