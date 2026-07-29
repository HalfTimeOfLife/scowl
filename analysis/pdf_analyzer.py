"""
analysis/pdf_analyzer.py — PDF file analyzer.

Scans the raw bytes of a PDF for structural and content-based indicators
without a heavy PDF-parsing dependency: embedded JavaScript, automatic-
action triggers, embedded files, suspicious object streams, and basic
structural integrity checks (header/trailer/xref/obj consistency).

Detection is done directly on the raw byte stream.
"""

import re

from analysis.model import Indicator, AnalysisResult
from analysis.utils import defang, extract_ips, extract_urls


JS_PATTERNS = {
    "/javascript",
    "/js",
}

AUTOOPEN_PATTERNS = {
    "/openaction",
    "/aa",
    "/launch",
}

EMBEDDED_FILE_PATTERNS = {
    "/embeddedfile",
    "/filespec",
}

OBJSTM_PATTERNS = {
    "/objstm",
    "/xrefstm",
}

HEADER_RE = re.compile(rb"%PDF-\d\.\d")
EOF_RE = re.compile(rb"%%EOF")
OBJ_RE = re.compile(rb"\d+\s+\d+\s+obj\b")
ENDOBJ_RE = re.compile(rb"endobj\b")


def _find_patterns(text_lower, patterns):
    """Return the subset of `patterns` present in `text_lower`."""
    return [p for p in patterns if p in text_lower]


def _check_structure(data):
    """Run basic structural integrity checks on the raw PDF bytes.

    Returns a list of human-readable issue descriptions. An empty list
    means no anomaly was found.
    """
    issues = []

    if not HEADER_RE.search(data[:1024]):
        issues.append("missing or malformed %PDF- header")

    if not EOF_RE.search(data[-1024:]):
        issues.append("missing %%EOF marker near end of file")

    has_trailer = b"trailer" in data
    has_xref_stream = (
        b"/XRefStm" in data or b"/Type/XRef" in data or b"/Type /XRef" in data
    )
    if not has_trailer and not has_xref_stream:
        issues.append("no trailer or cross-reference stream found")

    obj_count = len(OBJ_RE.findall(data))
    endobj_count = len(ENDOBJ_RE.findall(data))
    if obj_count != endobj_count:
        issues.append(
            f"mismatched obj/endobj count ({obj_count} obj vs {endobj_count} endobj)"
        )

    return issues


def analyze(file_info):
    """Extract indicators from a PDF file.

    Args:
        file_info: FileInfo instance with path set.

    Returns:
        AnalysisResult with embedded_javascript, autoopen_action, embedded_file,
        suspicious_object_stream, malformed_structure, embedded_url and
        embedded_ip indicators, or an error AnalysisResult if the file cannot
        be read.
    """
    indicators_list = []
    try:
        with open(file_info.path, "rb") as f:
            data = f.read()
    except Exception as e:
        return AnalysisResult(
            analyzer="pdf",
            indicators=[],
            metadata={},
            errors=[f"Failed to read file: {e}"],
        )

    decoded = data.decode("latin-1")
    text_lower = decoded.lower()

    js_patterns = _find_patterns(text_lower, JS_PATTERNS)
    for js_pattern in js_patterns:
        indicators_list.append(
            Indicator(
                name="embedded_javascript",
                description=f"Embedded JavaScript keyword found: '{js_pattern}'",
                severity="high",
                context={"pattern": js_pattern},
            )
        )

    autoopen_patterns = _find_patterns(text_lower, AUTOOPEN_PATTERNS)
    for autoopen_pattern in autoopen_patterns:
        indicators_list.append(
            Indicator(
                name="autoopen_action",
                description=f"Automatic action trigger found: '{autoopen_pattern}'",
                severity="high",
                context={"pattern": autoopen_pattern},
            )
        )

    embedded_file_patterns = _find_patterns(text_lower, EMBEDDED_FILE_PATTERNS)
    for embedded_file_pattern in embedded_file_patterns:
        indicators_list.append(
            Indicator(
                name="embedded_file",
                description=f"Embedded file object found: '{embedded_file_pattern}'",
                severity="medium",
                context={"pattern": embedded_file_pattern},
            )
        )

    objstm_patterns = _find_patterns(text_lower, OBJSTM_PATTERNS)
    for objstm_pattern in objstm_patterns:
        indicators_list.append(
            Indicator(
                name="suspicious_object_stream",
                description=f"Object/cross-reference stream found: '{objstm_pattern}'",
                severity="medium",
                context={"pattern": objstm_pattern},
            )
        )

    malformed_issues = _check_structure(data)
    for issue in malformed_issues:
        indicators_list.append(
            Indicator(
                name="malformed_structure",
                description=f"Structural anomaly: {issue}",
                severity="low",
                context={"issue": issue},
            )
        )

    urls = extract_urls(decoded)
    for url in urls:
        indicators_list.append(
            Indicator(
                name="embedded_url",
                description=f"URL found: {defang(url)}",
                severity="medium",
                context={"url": defang(url)},
            )
        )

    ips = extract_ips(decoded)
    for ip in ips:
        indicators_list.append(
            Indicator(
                name="embedded_ip",
                description=f"IP address found: {defang(ip)}",
                severity="low",
                context={"ip": defang(ip)},
            )
        )

    return AnalysisResult(
        analyzer="pdf",
        indicators=indicators_list,
        metadata={
            "size": len(data),
            "object_count": len(OBJ_RE.findall(data)),
        },
        errors=[],
    )
