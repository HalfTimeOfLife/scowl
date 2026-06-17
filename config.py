"""
Global configuration for scOWL.

Loads environment variables from .env and exposes constants used
across the bot, analyzers, scoring engine and integrations.
"""

import os

from dotenv import load_dotenv

load_dotenv()


# --- Discord ---------------------------------------------------------------

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "")

# Comma-separated list of channel names to watch, e.g. "general,faq"
# Empty (default) means scOWL listens to every channel on the server.
# Names are resolved to channel objects/IDs at startup in bot/main.py.
channels = os.getenv("WATCHED_CHANNEL_NAMES", "")
WATCHED_CHANNEL_NAMES = [
    c.strip().lower() for c in channels.split(",") if c.strip()
]

# Channel name used to post the welcome message on guild join.
# Empty (default) means scOWL falls back to the server's system channel.
WELCOME_CHANNEL_NAME = os.getenv("WELCOME_CHANNEL_NAME", "").strip().lower()


# --- VirusTotal --------------------------------------------------------------

VT_API_KEY = os.getenv("VT_API_KEY", "")


# --- File handling -----------------------------------------------------------

# 25 MB
MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024

TEMP_DOWNLOAD_DIR = os.getenv("TEMP_DOWNLOAD_DIR", "/tmp/scowl_uploads")


# --- Risk scoring ------------------------------------------------------------

# Raw score is 0-100, derived from  analyzer + ATT&CK findings.
# Thresholds below define the lower bound (inclusive) of each severity tier.
RISK_THRESHOLDS = {
    "LOW": 0,
    "MEDIUM": 30,
    "HIGH": 60,
    "CRITICAL": 85,
}


def get_risk_level(score):
    """Map a raw 0-100 score to its severity tier.

    Args:
        score: Raw risk score between 0 and 100.

    Returns:
        The severity tier name ("LOW", "MEDIUM", "HIGH", or "CRITICAL")
        whose threshold is the highest one not exceeding score.
    """
    level = "LOW"
    for tier in sorted(RISK_THRESHOLDS, key=RISK_THRESHOLDS.get):
        threshold = RISK_THRESHOLDS[tier]
        if score >= threshold:
            level = tier
    return level