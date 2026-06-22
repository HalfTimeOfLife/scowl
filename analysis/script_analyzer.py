"""
analysis/script_analyzer.py — Script file analyzer.

Extracts indicators from script files (PS1, BAT, CMD, VBS, JS, SH) via
regex-free pattern matching. Detection patterns are organized in per-language
subsets and resolved by file extension, falling back to the global union set
for unrecognized extensions.

The patterns aren't exhaustive, but they cover common indicators of malicious scripts.
Other indicators will be added in future versions.
"""

from pathlib import Path

from analysis.model import Indicator, AnalysisResult
from analysis.utils import defang, extract_ips, extract_urls


# --- DOWNLOAD_PATTERNS ----------------------------------------------------------

_DOWNLOAD_PS1 = {
    "iex",
    "invoke-expression",
    "invoke-webrequest",
    "iwr",
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "start-bitstransfer",
    "net.webclient",
}

_DOWNLOAD_BAT = {
    "curl",
    "wget",
    "certutil -urlcache",
    "bitsadmin",
}

_DOWNLOAD_VBS = {
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "msxml2.xmlhttp",
}

_DOWNLOAD_JS = {
    "xmlhttprequest",
    "activexobject",
    "fetch(",
}

_DOWNLOAD_SH = {
    "curl",
    "wget",
    "fetch",
}

DOWNLOAD_PATTERNS = _DOWNLOAD_PS1 | _DOWNLOAD_BAT | _DOWNLOAD_VBS | _DOWNLOAD_JS | _DOWNLOAD_SH

_DOWNLOAD_BY_EXT = {
    ".ps1": _DOWNLOAD_PS1,
    ".bat": _DOWNLOAD_BAT,
    ".cmd": _DOWNLOAD_BAT,
    ".vbs": _DOWNLOAD_VBS,
    ".js":  _DOWNLOAD_JS,
    ".sh":  _DOWNLOAD_SH,
}

# --- OBFUSCATION_PATTERNS -------------------------------------------------------

_OBFUSCATION_PS1 = {
    "base64",
    "frombase64string",
    "[char]",
    "-encodedcommand",
    "-enc ",
    "reflection.assembly",
    "::load(",
    "compress-archive",
    "expand-archive",
}

_OBFUSCATION_BAT = {
    "%var:~",
}

_OBFUSCATION_VBS = {
    "chr(",
    "charcode",
}

_OBFUSCATION_JS = {
    "chr(",
    "escape(",
    "unescape(",
    "charcode",
    "join(''",
    "string.fromcharcode(",
}

_OBFUSCATION_SH = {
    "base64 -d",
    "base64 --decode",
    "xxd",
    "od ",
}

OBFUSCATION_PATTERNS = (
    _OBFUSCATION_PS1 | _OBFUSCATION_BAT | _OBFUSCATION_VBS | _OBFUSCATION_JS | _OBFUSCATION_SH
)

_OBFUSCATION_BY_EXT = {
    ".ps1": _OBFUSCATION_PS1,
    ".bat": _OBFUSCATION_BAT,
    ".cmd": _OBFUSCATION_BAT,
    ".vbs": _OBFUSCATION_VBS,
    ".js":  _OBFUSCATION_JS,
    ".sh":  _OBFUSCATION_SH,
}


# --- SUSPICIOUS_CMDLETS ---------------------------------------------------------

_CMDLETS_PS1 = {
    "invoke-mimikatz",
    "add-mppreference",
    "set-mppreference",
    "set-executionpolicy",
    "invoke-shellcommand",
    "start-process",
    "new-object",
    "bypass",
    "hidden",
    "sekurlsa",
    "lsadump",
}

_CMDLETS_BAT = {
    "net user",
    "reg add",
    "schtasks",
    "sc config",
    "sc stop",
    "vssadmin delete",
    "bcdedit",
}

_CMDLETS_VBS = {
    "wscript",
    "cscript",
    "createobject",
}

_CMDLETS_JS = {
    "wscript",
    "cscript",
    "createobject",
}

_CMDLETS_SH = {
    "chmod +x",
    "/dev/tcp",
    "nc ",
    "ncat",
    "netcat",
    "useradd",
    "adduser",
    "crontab",
    "at ",
    "sudo ",
    "pkexec",
}

SUSPICIOUS_CMDLETS = (
    _CMDLETS_PS1 | _CMDLETS_BAT | _CMDLETS_VBS | _CMDLETS_JS | _CMDLETS_SH
)

_CMDLETS_BY_EXT = {
    ".ps1": _CMDLETS_PS1,
    ".bat": _CMDLETS_BAT,
    ".cmd": _CMDLETS_BAT,
    ".vbs": _CMDLETS_VBS,
    ".js":  _CMDLETS_JS,
    ".sh":  _CMDLETS_SH,
}


def analyze(file_info):
    """Extract indicators from a script file.

    Reads the file as text (UTF-8 with latin-1 fallback), then scans for
    embedded URLs, IPs, download patterns, obfuscation patterns and
    suspicious cmdlets. Patterns are resolved by file extension.

    Args:
        file_info: FileInfo instance with path and filename set.

    Returns:
        AnalysisResult with indicators grouped by category, or an error
        AnalysisResult if the file cannot be read.
    """
    indicators_list = []
    try:
        try:
            with open(file_info.path, "r", encoding="utf-8") as f:
                text = f.read()
        except UnicodeDecodeError:
            with open(file_info.path, "r", encoding="latin-1") as f:
                text = f.read()
    except Exception as e:
        return AnalysisResult(
            analyzer="script",
            indicators=[],
            metadata={},
            errors=[f"Failed to read file: {e}"],
        )

    text_lower = text.lower()

    # ---- URLs search ----
    urls = extract_urls(text)
    for url in urls:
        indicators_list.append(
            Indicator(
                name="embedded_url",
                description=f"URL found: {defang(url)}",
                severity="medium",
                context={"url": defang(url)},
            )
        )

    # ---- IPs search ----
    ips = extract_ips(text)
    for ip in ips:
        indicators_list.append(
            Indicator(
                name="embedded_ip",
                description=f"IP address found: {defang(ip)}",
                severity="low",
                context={"ip": defang(ip)},
            )
        )

    ext = Path(file_info.filename).suffix.lower()

    # ---- Downloads search ----
    for pattern in _DOWNLOAD_BY_EXT.get(ext, DOWNLOAD_PATTERNS):
        if pattern in text_lower:
            indicators_list.append(
                Indicator(
                    name="download_indicator",
                    description=f"Download pattern found: '{pattern}'",
                    severity="high",
                    context={"pattern": pattern},
                )
            )

    # ---- Obfuscation search ----
    for pattern in _OBFUSCATION_BY_EXT.get(ext, OBFUSCATION_PATTERNS):
        if pattern in text_lower:
            indicators_list.append(
                Indicator(
                    name="obfuscation_indicator",
                    description=f"Obfuscation pattern found: '{pattern}'",
                    severity="medium",
                    context={"pattern": pattern},
                )
            )

    # ---- Cmdlets search ----
    for pattern in _CMDLETS_BY_EXT.get(ext, SUSPICIOUS_CMDLETS):
        if pattern in text_lower:
            indicators_list.append(
                Indicator(
                    name="suspicious_cmdlet",
                    description=f"Suspicious cmdlet found: '{pattern}'",
                    severity="high",
                    context={"pattern": pattern},
                )
            )

    return AnalysisResult(
        analyzer="script",
        indicators=indicators_list,
        metadata={"line_count": len(text.splitlines())},
        errors=[],
    )