from analysis.model import AnalysisResult
from analysis import generic_analyzer
from pathlib import Path

import magic

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

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
}

def _get_analyzer(mime_type, filename):
    # ------------- TODO --------------
    # from analysis import pe_analyzer
    # from analysis import elf_analyzer
    # from analysis import office_analyzer
    # from analysis import script_analyzer
    #
    # if mime_type in PE_TYPES:
    #     return pe_analyzer.analyze
    # if mime_type in ELF_TYPES:
    #     return elf_analyzer.analyze
    # if mime_type in OFFICE_TYPES:
    #     return office_analyzer.analyze
    # if mime_type == "text/plain":
    #     ext = Path(filename).suffix.lower()
    #     if ext in SCRIPT_EXTENSIONS:
    #         return script_analyzer.analyze
    return generic_analyzer.analyze

def dispatch(file_info):
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