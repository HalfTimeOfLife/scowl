# ROADMAP

---

## v0.3 — PDF analysis

Adds indicator extraction specific to the PDF format.

- `analysis/pdf_analyzer.py`
- `tests/test_pdf.py`

---

## v0.4 — Office analysis

Adds indicator extraction specific to Office documents (macros, embedded objects, etc.).

- `analysis/office_analyzer.py`
- `tests/test_office.py`

---

## v0.5 — ELF analysis

Adds indicator extraction specific to ELF binaries.

- `analysis/elf_analyzer.py`
- `tests/test_elf.py`

---

## v0.6 — PE analysis

Adds indicator extraction specific to PE binaries.

- `analysis/pe_analyzer.py`
- `data/attck_patterns.json`
- `tests/test_pe.py`

---

## v0.7 — Scoring & Report

Analyzer results are aggregated, mapped to ATT&CK techniques, then turned into a risk score and a
presentable report instead of a raw dump. `/scan` becomes available, reusing the same pipeline as
the passive listener. `/status` is enriched with scan counters.

The scoring model is documented in `scoring/engine.py` (weighting rules, per-indicator base scores,
ATT&CK TID multipliers, aggregation logic).

- `scoring/attck_mapper.py`
- `scoring/engine.py` — includes inline documentation of the scoring model
- `reporting/json_exporter.py`
- `bot/commands.py` — `/scan` command
- `tests/test_scoring.py`

---

## v0.8 — VirusTotal Integration

A reputation lookup via VirusTotal runs in parallel with static analysis via `asyncio.gather`.
Results are merged into the final report. A SHA-256 cache (in-memory, optionally SQLite) prevents
redundant lookups and stays within the free-tier quota (4 req/min, 500 req/day).

- `integrations/virustotal.py` — lookup + SHA-256 deduplication cache
- `config.py` — `VT_CACHE_ENABLED` flag

---

## v0.9 — Moderation & Override

The bot acts on its own verdict: safe files are left untouched, uncertain files are flagged with a
warning embed, and dangerous files are deleted and replaced with a warning message instead of the
original upload.

Moderation is gated behind `MODERATION_ENABLED=false` by default. When disabled, the bot logs whatx
action it would have taken without acting — dry-run mode. Set `MODERATION_ENABLED=true` only after
validating verdicts in production.

`/force` lets authorized roles whitelist a file by hash to bypass blocking/warnings. Whitelisted
hashes are stored in `data/hash_allowlist.json` (gitignored; use `data/hash_allowlist.example.json`
as a template).

- `bot/commands.py` — `/force` command, moderation logic (delete + warn) on `on_message`
- `config.py` — `MODERATION_ENABLED` flag, moderation thresholds, authorized roles for `/force`
- `data/hash_allowlist.json` — whitelisted hashes added via `/force` (gitignored)
- `data/hash_allowlist.example.json` — empty template committed to the repo