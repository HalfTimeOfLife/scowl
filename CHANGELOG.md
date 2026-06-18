# CHANGELOG

## Setup

### Added
- `config.py` — environment loading, cross-platform `TEMP_DOWNLOAD_DIR`, risk thresholds
- `bot/main.py` — Discord bot setup, logging configuration (console + file handlers)
- `bot/commands.py` — `on_message` listener with file download, hashing and confirmation embed, `/help`, `/status`, welcome message on guild join
- `analysis/model.py` — `FileInfo` dataclass
- `analysis/utils.py` — `compute_hashes`, `safe_filename`, `format_size`