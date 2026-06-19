# ROADMAP

---

## v0.1 — Dispatcher & fallback

The received file is identified via its magic bytes and routed to the matching analyzer, with a text fallback when no specific analyzer applies.

- `analysis/dispatcher.py`
- `analysis/generic_analyzer.py`
- `reporting/embed_builder.py`

## v0.2 — Script analysis

Adds detection of indicators in script-based files (PS1/BAT/VBS/JS) via regex.

- `analysis/script_analyzer.py`

## v0.3 — PDF analysis

Adds indicator extraction specific to the PDF format.

- `analysis/pdf_analyzer.py`

## v0.4 — Office analysis

Adds indicator extraction specific to Office documents (macros, embedded objects, etc.).

- `analysis/office_analyzer.py`

## v0.5 — ELF analysis

Adds indicator extraction specific to ELF binaries.

- `analysis/elf_analyzer.py`

## v0.6 — PE analysis

Adds indicator extraction specific to PE binaries.

- `analysis/pe_analyzer.py`
- `data/attck_patterns.json`

## v0.7 — Scoring & Report

Analyzer results are aggregated, mapped to ATT&CK techniques, then turned into a risk score and a presentable report instead of a raw dump. `/scan` becomes available, reusing the same pipeline as the passive listener. `/status` is enriched with scan counters.

- `scoring/attck_mapper.py`
- `scoring/engine.py`
- `reporting/json_exporter.py`
- `bot/commands.py` — `/scan` command

## v0.8 — Integration & Testing

A reputation lookup via VirusTotal runs in parallel with static analysis, and the test suite is built out progressively.

- `integrations/virustotal.py`
- `tests/test_pe.py`, `tests/test_pdf.py`, `tests/test_scoring.py`

## v0.9 — Moderation & Override

The bot acts on its own verdict: safe files are left untouched, uncertain files are flagged with a warning embed, and dangerous files are deleted and replaced with a warning message instead of the original upload. `/force` lets authorized roles whitelist a file by hash to bypass blocking/warnings.

- `bot/commands.py` — `/force` command, moderation logic (delete + warn) on `on_message`
- `config.py` — moderation thresholds, authorized roles for `/force`
- `data/hash_allowlist.json` — whitelisted hashes added via `/force`