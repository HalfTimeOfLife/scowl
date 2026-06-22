"""
Unit tests for analysis/script_analyzer.py.
"""

from pathlib import Path
from analysis.script_analyzer import analyze
from analysis.model import FileInfo

SAMPLES = Path("tests/samples")

SAMPLE_FILES = [
    "test_ps1.ps1",
    "test_bat.bat",
    "test_cmd.cmd",
    "test_vbs.vbs",
    "test_js.js",
    "test_sh.sh",
]


def _make_file_info(filename):
    path = SAMPLES / filename
    return FileInfo(
        file_id=1,
        filename=filename,
        size=path.stat().st_size,
        channel="test",
        author="test",
        path=str(path),
    )

# --- PS1 test cases -------------------------------------------------------------

def test_ps1_downloads():
    result = analyze(_make_file_info("test_ps1.ps1"))
    downloads = [i for i in result.indicators if i.name == "download_indicator"]
    assert len(downloads) == 4

def test_ps1_obfuscation():
    result = analyze(_make_file_info("test_ps1.ps1"))
    obfuscations  = [i for i in result.indicators if i.name == "obfuscation_indicator"]
    assert len(obfuscations) == 5

def test_ps1_cmdlets():
    result = analyze(_make_file_info("test_ps1.ps1"))
    cmdlets  = [i for i in result.indicators if i.name == "suspicious_cmdlet"]
    assert len(cmdlets) == 6

# --- BAT test cases -------------------------------------------------------------

def test_bat_downloads():
    result = analyze(_make_file_info("test_bat.bat"))
    downloads = [i for i in result.indicators if i.name == "download_indicator"]
    assert len(downloads) == 4

def test_bat_obfuscation():
    result = analyze(_make_file_info("test_bat.bat"))
    obfuscations = [i for i in result.indicators if i.name == "obfuscation_indicator"]
    assert len(obfuscations) == 1

def test_bat_cmdlets():
    result = analyze(_make_file_info("test_bat.bat"))
    cmdlets = [i for i in result.indicators if i.name == "suspicious_cmdlet"]
    assert len(cmdlets) == 7

# --- JS test cases --------------------------------------------------------------

def test_js_downloads():
    result = analyze(_make_file_info("test_js.js"))
    downloads = [i for i in result.indicators if i.name == "download_indicator"]
    assert len(downloads) == 2

def test_js_obfuscation():
    result = analyze(_make_file_info("test_js.js"))
    obfuscations = [i for i in result.indicators if i.name == "obfuscation_indicator"]
    assert len(obfuscations) == 5

def test_js_cmdlets():
    result = analyze(_make_file_info("test_js.js"))
    cmdlets = [i for i in result.indicators if i.name == "suspicious_cmdlet"]
    assert len(cmdlets) == 3

# --- SH test cases --------------------------------------------------------------

def test_sh_downloads():
    result = analyze(_make_file_info("test_sh.sh"))
    downloads = [i for i in result.indicators if i.name == "download_indicator"]
    assert len(downloads) == 3

def test_sh_obfuscation():
    result = analyze(_make_file_info("test_sh.sh"))
    obfuscations = [i for i in result.indicators if i.name == "obfuscation_indicator"]
    assert len(obfuscations) == 4

def test_sh_cmdlets():
    result = analyze(_make_file_info("test_sh.sh"))
    cmdlets = [i for i in result.indicators if i.name == "suspicious_cmdlet"]
    assert len(cmdlets) == 7

# --- VBS test cases -------------------------------------------------------------

def test_vbs_downloads():
    result = analyze(_make_file_info("test_vbs.vbs"))
    downloads = [i for i in result.indicators if i.name == "download_indicator"]
    assert len(downloads) == 1

def test_vbs_obfuscation():
    result = analyze(_make_file_info("test_vbs.vbs"))
    obfuscations = [i for i in result.indicators if i.name == "obfuscation_indicator"]
    assert len(obfuscations) == 1

def test_vbs_cmdlets():
    result = analyze(_make_file_info("test_vbs.vbs"))
    cmdlets = [i for i in result.indicators if i.name == "suspicious_cmdlet"]
    assert len(cmdlets) == 3

# --- Common test cases ----------------------------------------------------------

def test_analyzer_name():
    for filename in SAMPLE_FILES:
        result = analyze(_make_file_info(filename))
        assert result.analyzer == "script", f"Failed for {filename}"

def test_metadata_line_count():
    for filename in SAMPLE_FILES:
        result = analyze(_make_file_info(filename))
        assert result.metadata["line_count"] > 0, f"Failed for {filename}"

def test_no_errors():
    for filename in SAMPLE_FILES:
        result = analyze(_make_file_info(filename))
        assert result.errors == [], f"Failed for {filename}"