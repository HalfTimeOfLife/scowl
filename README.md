<div align="center">
  <img src="scowl_icon.png" width="128" height="128"/>

  # scOWL -- Static malware triage bot for Discord
</div>

Discord bot that watches a server for uploaded files, automatically routes them to a format-specific static analyzer, and reports back a risk score, ATT&CK mapping and a VirusTotal reputation check.

> **Status:** scOWL is under active development. See [ROADMAP.md](ROADMAP.md) for the current state of each analyzer.

---

## Analysis Modules

`analysis/dispatcher.py` identifies the uploaded file via its magic bytes and routes it to the matching analyzer below. Each analyzer extracts the indicators specific to its format and returns them in a common interface consumed by the scoring engine. Files that don't match any known format fall back to `generic_analyzer.py`.

| Module | What it detects | Status |
|---|---|---|
| `generic_analyzer.py` | Plaintext fallback — printable strings, embedded URLs/IPs, suspicious keywords | WIP |
| `script_analyzer.py` | PS1/BAT/VBS/JS — obfuscation patterns, encoded payloads, suspicious cmdlets, regex-based, no heavy dependency | WIP |
| `pdf_analyzer.py` | Embedded JavaScript, auto-open actions, suspicious object streams, malformed structure | WIP |
| `office_analyzer.py` | VBA macros, embedded OLE objects, external template injection, DDE fields | WIP |
| `elf_analyzer.py` | Suspicious dynamic symbols, packed/stripped sections, anomalous segment layout | WIP |
| `pe_analyzer.py` | Suspicious imports, section entropy, malformed headers, packing indicators | WIP |

---

## Architecture of the project

Analyzers are fully **decoupled from scoring and reporting**. Each analyzer only extracts raw indicators; everything related to risk scoring and ATT&CK mapping lives in `scoring/`, and everything related to output formatting lives in `reporting/`.

```
scOWL/
├── config.py                      # Env loading, global constants (thresholds, max file size)
├── requirements.txt
├── bot/
│   ├── main.py                    # Discord connection, event loop
│   └── commands.py                # Attachment listener, temp file download
├── analysis/
│   ├── dispatcher.py              # Magic bytes → analyzer routing
│   ├── generic_analyzer.py
│   ├── script_analyzer.py
│   ├── pdf_analyzer.py
│   ├── office_analyzer.py
│   ├── elf_analyzer.py
│   └── pe_analyzer.py
├── scoring/
│   ├── attck_mapper.py            # Indicator → ATT&CK TID mapping
│   └── engine.py                  # Aggregates analyzer results, computes score
├── reporting/
│   ├── embed_builder.py           # Discord embed output
│   └── json_exporter.py           # Full JSON export
├── integrations/
│   └── virustotal.py              # VT lookup, run in parallel with static analysis
└── data/
    └── attck_patterns.json        # Indicator → ATT&CK TID reference data
```

---

## ATT&CK mapping

`data/attck_patterns.json` holds the reference data linking analyzer indicators to MITRE ATT&CK technique IDs. `scoring/attck_mapper.py` consumes this file to annotate each finding with its corresponding TID before scoring.

---

## Report generation

After analysis, scOWL replies in the Discord channel with an embed summarizing the verdict (risk score, matched ATT&CK techniques, VirusTotal reputation), built by `reporting/embed_builder.py`. A full machine-readable report is also produced via `reporting/json_exporter.py`, suitable for archival or pipeline integration.

---

## Requirements

- Python 3.10+
- A Discord bot token — see [.env.example](.env.example)
- A VirusTotal API key (optional, required for `integrations/virustotal.py`)
- `pip install -r requirements.txt`

---

## Getting Started

1. Copy `.env.example` to `.env` and fill in `DISCORD_TOKEN` and `VT_API_KEY`
2. Install dependencies: `pip install -r requirements.txt`
3. Run the bot: `python -m bot.main`
4. Invite the bot to your server and upload a file in a watched channel — scOWL analyzes it automatically

---

## Project status

See [ROADMAP.md](ROADMAP.md) for the planned release schedule.