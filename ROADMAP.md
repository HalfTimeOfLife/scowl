# ROADMAP

---

## Setup (no tag)

Project basics: configuration loading, dependencies, and a bot that listens for uploaded attachments but doesn't analyze them yet.

- `requirements.txt`
- `config.py`
- `bot/main.py`
- `bot/commands.py`

## v0.1 — Dispatcher & fallback

The received file is identified via its magic bytes and routed to the matching analyzer, with a text fallback when no specific analyzer applies.

- `analysis/dispatcher.py`
- `analysis/generic_analyzer.py`

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

Analyzer results are aggregated, mapped to ATT&CK techniques, then turned into a risk score and a presentable report instead of a raw dump.

- `scoring/attck_mapper.py`
- `scoring/engine.py`
- `reporting/embed_builder.py`
- `reporting/json_exporter.py`

## v0.8 — Integration & Testing

A reputation lookup via VirusTotal runs in parallel with static analysis, and the test suite is built out progressively.

- `integrations/virustotal.py`
- `tests/test_pe.py`, `tests/test_pdf.py`, `tests/test_scoring.py`