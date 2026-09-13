# VIDIC

AI-Powered Email Threat Intelligence & Detection Center

VIDIC is a desktop application for analyzing `.eml` files for phishing indicators. It parses the email, independently re-verifies its authentication (SPF, DKIM, DMARC), extracts indicators of compromise, optionally checks them against external threat-intelligence services, and runs the email's text through a local phishing-language classifier. All of this is combined into a single weighted risk score, with every contributing factor listed and explained.

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Installation](#installation)
- [Running tests](#running-tests)
- [Configuration](#configuration)
- [Risk scoring](#risk-scoring)
- [Project structure](#project-structure)
- [Roadmap](#roadmap)
- [License](#license)

## Features

- Independent SPF, DKIM, and DMARC verification against live DNS. The sender's own `Authentication-Results` header is never trusted, since it can be forged.
- Extraction of URLs, domains, IP addresses, email addresses, and attachment hashes. This runs fully offline with no network calls.
- Optional threat-intelligence lookups against VirusTotal, AbuseIPDB, URLhaus, and RDAP, with a local SQLite cache to avoid repeated lookups.
- A local DistilBERT-based classifier that scores the email's text for phishing-characteristic language, used alongside the reputation-based checks above.
- A weighted risk engine where every point in the final score is tied to a specific, named, and explained rule. The classifier's weight is scaled based on how much other evidence exists for a given email.
- Detection of executable and macro-enabled attachments by extension and MIME type.
- A local investigation history (SQLite-backed) that can be searched, renamed, and reviewed later.
- An offline/full mode toggle controlling whether extracted indicators are sent to external services.
- API keys are stored via the OS keychain (through `keyring`), not in a plaintext file.

## How it works

1. A `.eml` file is loaded, either by browsing or by dragging it into the application.
2. The Auth Engine independently verifies SPF, DKIM, and DMARC, and checks for a mismatch between the `From` and `Return-Path` addresses.
3. The IOC Extractor pulls out links, domains, IP addresses, email addresses, and attachment hashes.
4. If Full mode is enabled, each indicator is checked against VirusTotal, AbuseIPDB, URLhaus, and RDAP.
5. The phishing classifier scores the email's subject, body, and URLs for phishing-characteristic language.
6. The Risk Engine combines all of the above into a 0-100 score and a verdict (Safe, Suspicious, High Risk, or Critical Phishing), listing every rule that contributed to the score.
7. The result can be saved to history for later review.

## Installation

Requires Python 3.11 or later.

```bash
git clone https://github.com/MadjawBadpaw/VIDIC.git
cd VIDIC

python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt

python scripts/download_model.py

python -m vidic.main
```

The phishing classifier model (approximately 268 MB) is not stored in this repository. It is fetched from Hugging Face by `scripts/download_model.py` on first setup, into `vidic/models/distillbert/`.

## Running tests

It has many real phishing emails in "/tests" folder so you can check its working right away.

## Configuration

API keys and the enrichment mode are configured from the Settings dialog inside the application.

| Mode | Behavior |
|---|---|
| Offline / Local-only | Header parsing, live SPF/DKIM/DMARC checks (DNS lookups always run live), local IOC extraction, and the local phishing classifier. No email content is sent to external services. |
| Full | Everything in Offline mode, plus extracted links, domains, IP addresses, and attachment hashes are sent to VirusTotal, AbuseIPDB, URLhaus, and RDAP. |

Full mode should not be used when investigating a targeted attack that should not be tipped off, since submitting an attacker's own infrastructure to a public reputation service can alert them.

## Risk scoring

Each rule below contributes a fixed weight to the final score if it fires. The total is capped at 100.

| Rule | Weight |
|---|---|
| DMARC failure | 25 |
| DKIM failure | 20 |
| SPF failure | 15 |
| From / Return-Path mismatch | 15 |
| VirusTotal detection | 20 |
| URLhaus detection | 20 |
| AbuseIPDB high-risk IP | 15 |
| Domain registered under 30 days ago | 10 |
| Executable or macro-enabled attachment | 15 |
| Classifier, high confidence | 20-35 |
| Classifier, moderate confidence | 10-20 |

The classifier's weight varies based on how much other evidence exists for the email:

- If other rules already contribute a substantial score (strong corroboration), the classifier is weighted at its base value.
- If only a small amount of other evidence exists (weak corroboration), the classifier's weight is increased, since it is providing most of the signal.
- If no other rule fired at all, the classifier's weight is increased further, since it is the only signal available. This is common for newly registered phishing domains that have no reputation history yet.

Verdict thresholds:

| Score | Verdict |
|---|---|
| 90-100 | Critical Phishing |
| 70-89 | High Risk |
| 40-69 | Suspicious |
| 0-39 | Safe |

## Project structure

```
vidic/
├── core/
│   ├── parser.py            .eml parsing into a structured object (standard library only)
│   ├── auth.py              Independent SPF / DKIM / DMARC verification
│   ├── ioc.py               URL / domain / IP / email / hash extraction
│   ├── classifier.py        Phishing-language classifier (DistilBERT)
│   ├── risk.py              Weighted risk scoring engine
│   ├── summary.py           Plain-language explanations for fired rules
│   ├── report_formatter.py  HTML report generation
│   ├── db.py                SQLite-backed investigation history
│   ├── secrets.py           API key storage via keyring
│   └── threat_intel/        VirusTotal, AbuseIPDB, URLhaus, and RDAP clients
├── ui/
│   ├── main_window.py       Main application window
│   ├── drop_area.py         Drag-and-drop target for .eml files
│   ├── history_page.py      Investigation history browser
│   └── settings_page.py     API key and enrichment mode settings
└── main.py                  Application entry point
```

## Roadmap

- [x] Email parsing and header forensics
- [x] Independent SPF / DKIM / DMARC verification
- [x] IOC extraction
- [x] Threat intelligence integration
- [x] Local phishing-language classifier
- [x] Corroboration-based classifier weighting
- [x] Investigation history
- [ ] Relationship graph across analyzed emails (shared senders, domains, infrastructure)
- [ ] Rule-based phrase detection alongside the ML classifier
- [ ] Full report page redesign

## License

MIT.