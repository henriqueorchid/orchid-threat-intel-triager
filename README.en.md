[🇧🇷 Português](README.md) | 🇺🇸 English

# Orchid Threat Intel Triager

A CLI tool for triaging and enriching Indicators of Compromise (IoCs) across multiple Threat Intelligence providers in parallel. It accepts either a single indicator (IP, hash, domain, or URL) or a raw log file (`.txt`/`.csv`), strips internal noise before making any outbound request, queries up to 5 APIs concurrently, and outputs a consolidated verdict with a severity score and false-positive estimate.

---

## What it solves

During Tier-1/Tier-2 SOC triage, validating alerts usually means tab-hopping across VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX, and URLScan. Doing this by hand slows down every ticket and makes it easy to escalate false positives—such as a legitimate CDN/cloud IP flagged by 1 or 2 engines or a stale community pulse.

**Orchid Threat Intel Triager** automates that cross-check in the terminal:

- **Pre-flight sanitization**: extracts IoCs with Regex and uses Python's `ipaddress` module to drop private, reserved, loopback, link-local, multicast, and unspecified addresses (`10.0.0.15`, `192.168.x.x`, `127.0.0.1`, etc.) as well as common file extensions (`payload.exe`, `.dll`, `.log`), preventing internal topology leaks and unnecessary HTTP 400 errors.
- **Resilient parallel lookups**: dispatches API calls concurrently via `ThreadPoolExecutor`. If a provider hits a rate limit (`429`/`403`) or fails on the network, the validator isolates that source and rebalances the consensus across the remaining active APIs.
- **False-positive triage**: weighs detections against benign/legitimate signals (GreyNoise RIOT/benign classification, AbuseIPDB and OTX whitelists, VirusTotal community reputation, and shared CDN/cloud hosting).

---

## Architecture

The codebase strictly separates CLI presentation, IoC extraction, scoring/consensus, and API connectors:

```text
meu-ti-enricher/
├── main.py                  # ANSI CLI (Orchid palette), interactive menus, batch cadence, and reports
├── core/
│   ├── extractor.py         # Resilient log reader (.txt/.csv UTF-8/Latin-1), Regex, and ipaddress filter
│   └── validator.py         # ThreadPoolExecutor orchestration, dynamic weights, consensus, and FP engine
├── integrations/
│   ├── virustotal.py        # VirusTotal API v3 connector (IP, Hash, Domain, URL)
│   ├── abuseipdb.py         # AbuseIPDB API v2 connector (IP)
│   ├── alienvault.py        # AlienVault OTX API v1 connector (IP, Hash, Domain, URL)
│   ├── urlscan.py           # URLScan.io Search + Result API connector (IP, Domain, URL)
│   └── greynoise.py         # GreyNoise Community API v3 connector (IP)
├── docs/images/             # CLI screenshots
├── .env.example             # Environment variable template for API keys
├── requirements.txt         # Python dependencies
└── LICENSE                  # MIT License
```

### Connector return contract (`integrations/`)

Every connector returns a standardized dictionary containing `"source"` and follows a single state contract:
- **Success (`200`)**: normalized telemetry fields from that provider.
- **Rate limit / Quota (`429` or `403`)**: `{"source": ..., "rate_limited": True, "aviso": ...}` — excluded from weight calculation without aborting the run.
- **No record or invalid/non-routable indicator (`404`, `422`, or `400`)**: `{"source": ..., "aviso": ...}` — handled gracefully as uncatalogued or non-routable.
- **Invalid credentials or network failure (`401`, timeout, `RequestException`)**: `{"source": ..., "erro": ...}`.

---

## Consensus and false-positive engine (`core/validator.py`)

### 1. Reliability weights by IoC type

Each indicator is routed only to compatible providers and scored from `0` to `100` using weights summing to `1.0`:

| IoC Type | VirusTotal | AbuseIPDB | GreyNoise | AlienVault OTX | URLScan.io |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **IP** | `0.20` | `0.35` | `0.25` | `0.12` | `0.08` |
| **Hash (MD5 / SHA-256)** | `0.75` | — | — | `0.25` | — |
| **Domain / URL** | `0.40` | — | — | `0.20` | `0.40` |

- **Dynamic renormalization**: if an API hits a rate limit or network error, it is omitted from `soma_pesos_ativos` and the weighted average is computed over the providers that responded.
- **URLScan no-history dampening**: when URLScan.io returns `"aviso"` (no prior scan history), its weight is scaled to `25%` (`weight * 0.25`) so a lack of web scans does not dilute threats confirmed by VirusTotal or AbuseIPDB.
- **Convergence and synergy boosts**: `>= 3` malicious sources add `+12.0` to severity; OTX Threat Actor/APT attribution adds `+10.0`; strong convergence between AbuseIPDB and GreyNoise (`>= 80`) adds `+15.0`.

### 2. Severity tiers

| Score | Level |
| :--- | :--- |
| `0.0` | `LIMPO / INFORMATIVO` (Clean / Info) |
| `0.1 – 24.9` | `BAIXO` (Low) |
| `25.0 – 54.9` | `MÉDIO` (Medium) |
| `55.0 – 79.9` | `ALTO` (High) |
| `80.0 – 100.0` | `CRÍTICO` (Critical) |

### 3. False-positive probability (0% to 100%)

When no provider detects malicious activity, false-positive status is `N/A`. Once any detection is present, the engine starts at a neutral `50%` baseline and adjusts for conflicting or corroborating evidence:

- **Signals increasing false-positive likelihood (and dampening severity):**
  - GreyNoise `riot: True` (known legitimate infrastructure such as public DNS or cloud services): `+45%` FP, severity `× 0.25`.
  - GreyNoise `classification == "benign"`: `+35%` FP, severity `× 0.45`.
  - Official AbuseIPDB whitelist (`+35%` FP, severity `× 0.40`) or AlienVault OTX validation/whitelist (`+30%` FP, severity `× 0.50`).
  - Marginal VirusTotal detection (`1–2` malicious engines vs `>= 40` harmless): `+30%` FP.
  - Positive VirusTotal community reputation (`reputation > 5`): `+25%` FP, severity `× 0.60`.
  - Alert isolated to AlienVault OTX community pulses with `>= 2` queried providers: `+28%` FP.
  - Shared CDN/Cloud hosting (Cloudflare, Akamai, Fastly, AWS, Google, Azure, Incapsula) when severity `< 75`: `+15%` FP.

- **Signals reducing false-positive likelihood:**
  - Broad VirusTotal engine consensus (`>= 15`: `-42%`; `>= 6`: `-25%`; `>= 3`: `-10%`) and negative community reputation (`<= -10`: `-20%`).
  - AbuseIPDB multi-network consensus (`score >= 80` across `>= 10` distinct reporting networks): `-30%`.
  - GreyNoise `classification == "malicious"`: `-30%`.
  - URLScan.io sandbox verdict `malicious: True`: `-30%`.
  - Multi-source agreement (`>= 3` sources: `-25%`; `2` sources: `-15%`).

---

## Installation and `.env` setup

Requires **Python 3.10+** and free-tier API keys for the enabled providers.

```bash
git clone https://github.com/henriqueorchid/orchid-threat-intel-triager.git
cd orchid-threat-intel-triager

python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows (PowerShell): .venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Create your `.env` file from the template (`.env` is already ignored in `.gitignore`):

```bash
cp .env.example .env
```

Fill in your own API keys:

| Variable | Provider | Where to get it | Free Tier Notes |
| :--- | :--- | :--- | :--- |
| `VT_API_KEY` | VirusTotal | [virustotal.com](https://www.virustotal.com/) | Typically 4 req/min and 500 req/day |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | [abuseipdb.com](https://www.abuseipdb.com/api) | Used for IP reputation lookups |
| `ALIENVAULT_API_KEY` | AlienVault OTX | [otx.alienvault.com](https://otx.alienvault.com/) | Pulses, tags, threat actors, whitelists |
| `URLSCAN_API_KEY` | URLScan.io | [urlscan.io](https://urlscan.io/user/apikey) | Queries prior scan results and verdicts |
| `GREYNOISE_API_KEY` | GreyNoise | [viz.greynoise.io](https://viz.greynoise.io/account/api-key) | Community API (RIOT / scanner noise) |

---

## Usage and demo

Launch the interactive CLI:

```bash
python main.py
```

Main menu options:
- `[1]` **Investigate IP Address** — queries VT, AbuseIPDB, OTX, GreyNoise, and URLScan.
- `[2]` **Investigate Hash (MD5 / SHA-256)** — queries VT and AlienVault OTX.
- `[3]` **Investigate URL / Domain** — queries URLScan, VT, and AlienVault OTX.
- `[4]` **Batch-scan Log File (`.txt` / `.csv`)** — reads UTF-8 or Latin-1 files, extracts public/routable IoCs, and lets you choose between:
  - **Safe Mode** (`15s` delay between indicators to stay within VirusTotal's 4 req/min free limit);
  - **Fast Mode** (no delay; if any API hits `429`, the remaining providers still complete the triage).

### Screenshots

**1. Main menu and triage options (`[1]` to `[4]`):**

![Orchid Threat Intel Triager main menu](docs/images/print%201.jpg)

**2. Single Hash lookup via option `[2]` (WannaCry SHA-256 example):**

Submitting a WannaCry SHA-256 hash in option `[2]` queries VirusTotal and AlienVault OTX in parallel, correlating malware family classification (`trojan.wannacry/wanna`), threat actor attribution (`Lazarus Group, WannaCry`), and community reputation (`-1811`) into a `100.0/100 (CRÍTICO)` verdict with `1.0%` false-positive probability.

![WannaCry hash verdict via option 2](docs/images/print%202.jpg)

### Sample `.txt` log scan (option `[4]`)

Screenshots **3** and **4** below come from batch-scanning the following `.txt` log file, which mixes internal IPs (`10.0.0.15`, `10.0.0.42`), an executable filename (`payload.exe`), and external indicators:

```text
[2026-11-10 12:10:04] FW-DROP SRC=161.118.214.16 DST=10.0.0.15 PROTO=TCP DPT=443
[2026-11-10 12:11:19] DNS-QUERY client=10.0.0.42 query=word-template.net action=flagged
[2026-11-10 12:12:02] EDR-ALERT host=WKST-09 file=payload.exe sha256=1941cbf3b6e705550f373990b5702220b2c1db0dceaf252ded42cdaff295c54f
[2026-11-10 12:14:55] PROXY-ALLOW dst_ip=8.8.8.8 
url=eng-polymarket.com
```

The extractor automatically drops `10.0.0.15`, `10.0.0.42`, and `payload.exe`, sending only the **5 routable IoCs** (`161.118.214.16`, `8.8.8.8`, `word-template.net`, `eng-polymarket.com`, and the SHA-256 hash) for parallel enrichment and final consolidation.

**3. IP verdict during the `.txt` log scan (`161.118.214.16`):**

![IP lookup during txt log scan](docs/images/print%203.jpg)

**4. Final executive summary of the `.txt` log scan:**

![Batch txt log scan executive summary](docs/images/print%204.jpg)

---

## License and author

Distributed under the **MIT License**. See [LICENSE](LICENSE) for details.

**Author:** Henrique 'Orchid' Silva (2026)
