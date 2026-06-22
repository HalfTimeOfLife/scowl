"""
analysis/model.py — Core data models for the analysis pipeline.

Defines the dataclasses shared across analyzers, scoring and reporting.
"""

from dataclasses import dataclass


@dataclass
class FileInfo:
    """Metadata for a file received from Discord.

    Attributes:
        file_id: Discord attachment ID.
        filename: Original filename from the Discord attachment.
        size: File size in bytes.
        channel: Name of the Discord channel where the file was uploaded.
        author: String representation of the Discord user who uploaded the file.
        path: Absolute path to the downloaded file on disk.
        sha256: SHA-256 hex digest of the file.
        sha1: SHA-1 hex digest of the file.
        md5: MD5 hex digest of the file.
        content_type: MIME type detected by libmagic (overrides Discord's value).
    """
    file_id: int
    filename: str
    size: int
    channel: str
    author: str
    path: str = ""
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    content_type: str = ""


@dataclass
class Indicator:
    """A single suspicious finding extracted by an analyzer.

    Attributes:
        name: Indicator type (e.g. embedded_url, download_indicator).
        description: Human-readable description of the finding.
        severity: Severity level (low, medium, high).
        context: Analyzer-specific key/value pairs for the finding.
    """
    name: str
    description: str
    severity: str
    context: dict


@dataclass
class AnalysisResult:
    """Output of a single analyzer run.

    Attributes:
        analyzer: Name of the analyzer that produced this result.
        indicators: List of indicators extracted from the file.
        metadata: Analyzer-specific metadata (e.g. line_count, string_count).
        errors: List of error messages if the analysis failed partially or fully.
    """
    analyzer: str
    indicators: list[Indicator]
    metadata: dict
    errors: list[str]