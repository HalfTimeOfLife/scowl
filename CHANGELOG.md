# CHANGELOG - scOWL

---

## v0.3 — PDF analysis

### Added
- `analysis/pdf_analyzer.py` — PDF indicator extraction via raw byte/keyword scanning, no PDF-parsing dependency: `embedded_javascript` (`/JavaScript`, `/JS`), `autoopen_action` (`/OpenAction`, `/AA`, `/Launch`), `embedded_file` (`/EmbeddedFile`, `/Filespec`), `suspicious_object_stream` (`/ObjStm`, `/XRefStm`), `malformed_structure` (header/EOF/trailer/obj-endobj checks — `severity="low"`, since a genuinely corrupted file triggers the same signal as a deliberately evasive one); reuses `extract_urls`/`extract_ips` from `utils.py` for `embedded_url`/`embedded_ip`
- `data/attck_patterns.json` — ATT&CK reference data (`default`/`patterns` schema: category-level default technique, with per-pattern overrides only where the default would be misleading) covering `embedded_url`, `embedded_ip`, `download_indicator`, `obfuscation_indicator`, `suspicious_cmdlet` (pre-v0.3 analyzers) plus the new PDF indicators. Not yet consumed by any mapper (planned for v0.7)
- `tests/test_pdf.py` — unit tests for `analysis/pdf_analyzer.py`
- `tests/samples/test_pdf_malicious.pdf`, `test_pdf_malformed.pdf`, `test_pdf_clean.pdf` — text-based PDF-syntax fixtures (not valid binary PDFs)

### Changed
- `analysis/dispatcher.py` — added `PDF_TYPES` (`application/pdf`) routing; added an extension-based fallback (`FALLBACK_EXTENSIONS`) so a `.pdf` file whose magic bytes go unrecognized (e.g. a deliberately stripped `%PDF-` header) still routes to `pdf_analyzer` instead of `generic_analyzer`; this fallback appends an `extension_mimetype_mismatch` indicator (mapped to ATT&CK T1036.008 — Masquerading) so the mismatch itself is visible in the report
- `reporting/embed_builder.py` — added `embedded_javascript`, `autoopen_action`, `embedded_file`, `suspicious_object_stream`, `malformed_structure` and `extension_mimetype_mismatch` fields; fields remain hidden when empty
- `README.md` — `pdf_analyzer.py` status updated to `UP`
- `.gitignore` — added `.pytest_cache/`

---

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



