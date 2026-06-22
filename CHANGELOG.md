# CHANGELOG

## v0.2 — Script analysis

### Added
- `analysis/script_analyzer.py` — PS1/BAT/CMD/VBS/JS/SH indicator extraction via regex; per-language pattern subsets (`_DOWNLOAD_PS1`, `_CMDLETS_BAT`, etc.) unified via set union, resolved per file extension via `_BY_EXT` dicts with fallback to globals
- `tests/test_utils.py` — unit tests for `analysis/utils.py`
- `tests/test_generic.py` — unit tests for `analysis/generic_analyzer.py`
- `tests/test_dispatcher.py` — unit tests for `analysis/dispatcher.py`
- `tests/test_script.py` — unit tests for `analysis/script_analyzer.py`
- `tests/README.md` — test suite documentation
- `tests/samples/` — sample files for `test_script.py` and `test_generic.py`

### Changed
- `analysis/utils.py` — `extract_urls` and `extract_ips` extracted from `generic_analyzer` for reuse across analyzers; URL regex minimum length reduced from 8 to 4 characters
- `analysis/dispatcher.py` — added `text/x-msdos-batch` and `text/x-shellscript` to script MIME types; added `.sh` to `SCRIPT_EXTENSIONS`
- `analysis/generic_analyzer.py` — removed `SUSPICIOUS_KEYWORDS` and keyword detection; URLs and IPs now use shared `extract_urls`/`extract_ips` from `utils.py`
- `reporting/embed_builder.py` — added `download_indicator`, `obfuscation_indicator` and `suspicious_cmdlet` fields; fields are now only displayed when non-empty
- `README.md` — updated analyzer status and module descriptions

---

## v0.1 — Dispatcher & fallback

### Added
- `analysis/model.py` — `Indicator` and `AnalysisResult` dataclasses
- `analysis/utils.py` — `defang` helper for safe display of URLs and IPs
- `analysis/dispatcher.py` — magic bytes identification and analyzer routing
- `analysis/generic_analyzer.py` — printable string extraction, URL/IP regex detection
- `reporting/embed_builder.py` — Discord embed builder with verdict, color coding and per-category indicator grouping
- `bot/commands.py` — analysis pipeline integration (`dispatch`, `build_result_embed`)

---

## Setup

### Added
- `config.py` — environment loading, cross-platform `TEMP_DOWNLOAD_DIR`, risk thresholds
- `bot/main.py` — Discord bot setup, logging configuration (console + file handlers)
- `bot/commands.py` — `on_message` listener with file download, hashing and confirmation embed, `/help`, `/status`, welcome message on guild join
- `analysis/model.py` — `FileInfo` dataclass
- `analysis/utils.py` — `compute_hashes`, `safe_filename`, `format_size`



