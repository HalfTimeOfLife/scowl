"""
config.py — Global configuration for scOWL.

Loads environment variables from .env and exposes constants used
across the bot, analyzers, scoring engine and integrations.
"""

import os
import tempfile

from dotenv import load_dotenv

load_dotenv()


# --- Discord -----------------------------------------------------------------

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")

# Comma-separated list of channel names to watch, e.g. "malware-analysis,samples".
# Empty (default) means scOWL listens to every channel on the server.
channels = os.getenv("WATCHED_CHANNEL_NAMES", "")
WATCHED_CHANNEL_NAMES = [
    c.strip().lower() for c in channels.split(",") if c.strip()
]

# Channel name where scOWL posts its welcome message on guild join.
# Empty (default) means scOWL falls back to the server's system channel.
WELCOME_CHANNEL_NAME = os.getenv("WELCOME_CHANNEL_NAME", "").strip().lower()


# --- VirusTotal --------------------------------------------------------------

VT_API_KEY = os.getenv("VT_API_KEY", "")


# --- File handling -----------------------------------------------------------

# Maximum attachment size accepted for analysis (25 MB).
MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024

# Temporary directory for downloaded attachments.
# Defaults to the system temp directory if not set in .env.
TEMP_DOWNLOAD_DIR = os.getenv("TEMP_DOWNLOAD_DIR", "").strip() or os.path.join(
    tempfile.gettempdir(), "scowl_uploads"
)