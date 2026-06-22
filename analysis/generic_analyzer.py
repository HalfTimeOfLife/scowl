"""
analysis/generic_analyzer.py — Plaintext analyzer.

Extracts printable strings from raw bytes and scans them for
embedded URLs and IP addresses. Used as a fallback for files
that don't match any specific analyzer.

Note: an IP embedded in a URL produces both an embedded_url
and an embedded_ip indicator.
"""

from analysis.model import Indicator, AnalysisResult
from analysis.utils import defang, extract_urls, extract_ips


def _extract_strings(data, min_length=4):
    """Extract contiguous printable ASCII strings from raw bytes.

    Args:
        data: Raw bytes to scan.
        min_length: Minimum string length to include (default: 4).

    Returns:
        List of extracted strings.
    """
    current = []
    results = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                results.append("".join(current))
            current = []
    if len(current) >= min_length:
        results.append("".join(current))
    return results


def analyze(file_info):
    """Extract indicators from a file by scanning its printable strings.

    Args:
        file_info: FileInfo instance with path set.

    Returns:
        AnalysisResult with embedded_url and embedded_ip indicators,
        or an error AnalysisResult if the file cannot be read.
    """
    indicators_list = []
    try:
        with open(file_info.path, "rb") as f:
            data = f.read()
    except Exception as e:
        return AnalysisResult(
            analyzer="generic",
            indicators=[],
            metadata={},
            errors=[f"Failed to read file: {e}"],
        )

    extracted_strings = _extract_strings(data)

    for extracted_string in extracted_strings:
        urls = extract_urls(extracted_string)
        for url in urls:
            indicators_list.append(
                Indicator(
                    name="embedded_url",
                    description=f"URL found: {defang(url)}",
                    severity="medium",
                    context={"url": defang(url)},
                )
            )

        ips = extract_ips(extracted_string)
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
        analyzer="generic",
        indicators=indicators_list,
        metadata={"string_count": len(extracted_strings)},
        errors=[],
    )