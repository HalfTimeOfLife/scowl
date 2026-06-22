"""
analysis/dispatcher.py — Analyzer routing.

Detects the MIME type of a file via libmagic and routes it to the
matching analyzer. Falls back to generic_analyzer for unknown formats.
"""

from pathlib import Path

import magic

from analysis import generic_analyzer
from analysis import script_analyzer
from analysis.model import AnalysisResult


PE_TYPES = {
    "application/x-dosexec",
    "application/x-msdownload",
}

ELF_TYPES = {
    "application/x-sharedlib",
    "application/x-executable",
}

OFFICE_TYPES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
}

SCRIPT_MIME_TYPES = {
    "text/plain",
    "text/x-shellscript",
    "text/x-msdos-batch",
}

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".sh",
}


def _get_analyzer(mime_type, filename):
    """Select the appropriate analyzer for a given MIME type and filename.

    Args:
        mime_type: MIME type string detected by libmagic.
        filename: Original filename, used to resolve the extension for script routing.

    Returns:
        An analyzer callable that accepts a FileInfo and returns an AnalysisResult.
    """
    # ------------- TODO --------------
    # from analysis import pe_analyzer
    # from analysis import elf_analyzer
    # from analysis import office_analyzer
    #
    # if mime_type in PE_TYPES:
    #     return pe_analyzer.analyze
    # if mime_type in ELF_TYPES:
    #     return elf_analyzer.analyze
    # if mime_type in OFFICE_TYPES:
    #     return office_analyzer.analyze
    if mime_type in SCRIPT_MIME_TYPES:
        ext = Path(filename).suffix.lower()
        if ext in SCRIPT_EXTENSIONS:
            return script_analyzer.analyze
    return generic_analyzer.analyze


def dispatch(file_info):
    """Identify a file's type and route it to the matching analyzer.

    Detects the MIME type via libmagic (overriding Discord's content_type
    to prevent extension spoofing), then delegates to the appropriate analyzer.

    Args:
        file_info: FileInfo instance with at least path and filename set.

    Returns:
        AnalysisResult from the selected analyzer, or an error AnalysisResult
        if MIME detection fails.
    """
    try:
        mime_type = magic.from_file(file_info.path, mime=True)
    except Exception as e:
        return AnalysisResult(
            analyzer="dispatcher",
            indicators=[],
            metadata={},
            errors=[f"Failed to determine file type: {e}"],
        )

    file_info.content_type = mime_type

    analyzer = _get_analyzer(mime_type, file_info.filename)
    return analyzer(file_info)