# CHANGELOG

## Setup

### Added
- `config.py` — environment loading, cross-platform `TEMP_DOWNLOAD_DIR`, risk thresholds
- `bot/main.py` — Discord bot setup, logging configuration (console + file handlers)
- `bot/commands.py` — `on_message` listener with file download, hashing and confirmation embed, `/help`, `/status`, welcome message on guild join
- `analysis/model.py` — `FileInfo` dataclass
- `analysis/utils.py` — `compute_hashes`, `safe_filename`, `format_size`

## v0.1 — Dispatcher & fallback

### Added
- `analysis/model.py` — `Indicator` and `AnalysisResult` dataclasses
- `analysis/utils.py` — `defang` helper for safe display of URLs and IPs
- `analysis/dispatcher.py` — magic bytes identification and analyzer routing
- `analysis/generic_analyzer.py` — printable string extraction, URL/IP regex detection, suspicious keyword matching
- `reporting/embed_builder.py` — Discord embed builder with verdict, color coding and per-category indicator grouping
- `bot/commands.py` — analysis pipeline integration (`dispatch`, `build_result_embed`)