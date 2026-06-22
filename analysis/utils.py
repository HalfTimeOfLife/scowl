"""
analysis/utils.py — Shared helpers used across the pipeline.
"""

import hashlib
import re

CHUNK_SIZE = 65536

URL_RE = re.compile(r"https?://[^\s\"'<>]{4,}", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def compute_hashes(path):
    """Compute SHA-256, SHA-1 and MD5 digests for a file.

    Reads the file in fixed-size chunks to avoid loading it entirely
    into memory.

    Args:
        path: Path to the file on disk.

    Returns:
        A dict with keys "sha256", "sha1" and "md5", each mapping
        to the corresponding hex digest string.
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def safe_filename(attachment_id, filename):
    """Build a filesystem-safe name for a downloaded attachment.

    Prefixes the attachment ID and sanitizes the original filename
    to remove characters that are unsafe in file paths.

    Args:
        attachment_id: Discord attachment ID (used as unique prefix).
        filename: Original filename from the Discord attachment.

    Returns:
        A sanitized filename string of the form "{attachment_id}_{stem}.{ext}".
    """
    stem, _, ext = filename.rpartition(".")
    stem_clean = re.sub(r"[^\w\-]", "_", stem)
    ext_clean = re.sub(r"[^\w]", "_", ext)
    return f"{attachment_id}_{stem_clean}.{ext_clean}"


def format_size(size):
    """Format a file size in bytes to a human-readable string.

    Args:
        size: File size in bytes.

    Returns:
        A human-readable string with the appropriate unit (B, KB, or MB).
    """
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def defang(text: str) -> str:
    """Defang a string for safe display.

    Replaces protocol prefixes and dots to prevent accidental
    hyperlinking or execution of embedded URLs and IPs.

    Args:
        text: The string to defang.

    Returns:
        The defanged string, or the original string if empty.
    """
    if not text:
        return text

    text = text.replace("http://", "hxxp://")
    text = text.replace("https://", "hxxps://")
    text = text.replace(".", "[.]")
    text = text.replace("@", "[at]")

    return text


def extract_urls(text):
    """Extract URLs from a string.

    Args:
        text: The string to search.

    Returns:
        A list of extracted URL strings.
    """
    return URL_RE.findall(text)


def extract_ips(text):
    """Extract IP addresses from a string.

    Args:
        text: The string to search.

    Returns:
        A list of extracted IP address strings.
    """
    return IP_RE.findall(text)