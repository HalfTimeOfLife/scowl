import re
from analysis.model import Indicator, AnalysisResult
from analysis.utils import defang

SUSPICIOUS_KEYWORDS = {
    "cmd.exe",
    "powershell",
    "wget",
    "curl",
    "base64",
    "eval",
    "shellcode",
    "net user",
    "reg add",
    "schtasks",
    "certutil",
    "wscript",
    "cscript"
}

URL_RE = re.compile(r"https?://[^\s\"'<>]{8,}", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _extract_strings(data, min_length=4):
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
        
    # ---- String extraction ----
    extracted_strings = _extract_strings(data)
    
    for extracted_string in extracted_strings:
        
        # ---- URLs search ----
        urls = URL_RE.findall(extracted_string)
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
        ips = IP_RE.findall(extracted_string)
        for ip in ips:
            indicators_list.append(
                Indicator(
                    name="embedded_ip",
                    description=f"IP address found: {defang(ip)}",
                    severity="low",
                    context={"ip": defang(ip)},
                )
            )
            
        # ---- Keyword search ----
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in extracted_string.lower():
                indicators_list.append(
                    Indicator(
                        name="suspicious_keyword",
                        description=f"Suspicious keyword found: '{keyword}'",
                        severity="medium",
                        context={"keyword": keyword},
                    )
                )
    return AnalysisResult(
                analyzer="generic",
                indicators=indicators_list,
                metadata={"string_count": len(extracted_strings)},
                errors=[]
            )