<div align="center">
  <img src="scowl_icon.png" width="128" height="128"/>

  # scOWL -- Static malware triage bot for Discord
</div>

Discord bot that watches a server for uploaded files, automatically routes them to a format-specific static analyzer, and reports back a risk score, ATT&CK mapping and a VirusTotal reputation check.

> **Status:** scOWL is under active development. See [ROADMAP.md](ROADMAP.md) for the current state of each analyzer.

> ⚠️ **Security Warning**
> - scOWL downloads and stores files uploaded to your Discord server, including potentially malicious ones.
> - Always run scOWL in an isolated environment (VM, container, sandbox).
> - Never run it on a host machine.
> - Temporary files are stored in `TEMP_DOWNLOAD_DIR` and should be cleaned up regularly.

---

## Analysis Modules

`analysis/dispatcher.py` identifies the uploaded file via its magic bytes and routes it to the matching analyzer below. Each analyzer extracts the indicators specific to its format and returns them in a common interface consumed by the scoring engine. Files that don't match any known format fall back to `generic_analyzer.py`.

| Module | What it detects | Status |
|---|---|---|
| `generic_analyzer.py` | Plaintext fallback — printable strings, embedded URLs/IPs, suspicious keywords | UP |
| `script_analyzer.py` | PS1/BAT/VBS/JS — obfuscation patterns, encoded payloads, suspicious cmdlets, regex-based, no heavy dependency | Planned |
| `pdf_analyzer.py` | Embedded JavaScript, auto-open actions, suspicious object streams, malformed structure | Planned |
| `office_analyzer.py` | VBA macros, embedded OLE objects, external template injection, DDE fields | Planned |
| `elf_analyzer.py` | Suspicious dynamic symbols, packed/stripped sections, anomalous segment layout | Planned |
| `pe_analyzer.py` | Suspicious imports, section entropy, malformed headers, packing indicators | Planned |

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
│   ├── model.py                   # FileInfo dataclass
│   ├── utils.py                   # utility functions
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
- **Windows only:** `pip install python-magic-bin` (replaces `python-magic`)

---

## Configuration

Copy `.env.example` to `.env` and fill in the following variables:

| Variable | Required | Description |
|---|---|---|
| `DISCORD_TOKEN` | Yes | Your bot token from the [Discord Developer Portal](https://discord.com/developers/applications) |
| `VT_API_KEY` | No | Your VirusTotal API key — leave empty to disable VT lookups |
| `WATCHED_CHANNEL_NAMES` | No | Comma-separated list of channel names to watch (e.g. `malware-analysis,samples`). Leave empty to watch all channels |
| `WELCOME_CHANNEL_NAME` | No | Channel name where scOWL posts its welcome message on server join. Leave empty to use the server's system channel |
| `TEMP_DOWNLOAD_DIR` | No | Absolute path to the temporary download directory. Defaults to `/tmp/scowl_uploads` or `C:\Users\<user>\AppData\Local\Temp\scowl_uploads` |

---

## Getting Started

1. Copy `.env.example` to `.env` and fill in `DISCORD_TOKEN` and `VT_API_KEY`
2. Install dependencies: `pip install -r requirements.txt`
   - **Windows only:** also run `pip install python-magic-bin`
3. Run the bot: `python -m bot.main`
4. Invite the bot to your server and upload a file in a watched channel — scOWL analyzes it automatically

---

## Project status

See [ROADMAP.md](ROADMAP.md) for the planned release schedule.