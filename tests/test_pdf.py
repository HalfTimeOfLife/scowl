"""
Unit tests for analysis/pdf_analyzer.py.
"""

from pathlib import Path
from analysis.pdf_analyzer import analyze
from analysis.model import FileInfo

SAMPLES = Path("tests/samples")


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


# --- Malicious PDF test ---------------------------------------------------------


def test_malicious_embedded_javascript():
    result = analyze(_make_file_info("test_pdf_malicious.pdf"))
    js = [i for i in result.indicators if i.name == "embedded_javascript"]
    assert len(js) == 2


def test_malicious_autoopen_action():
    result = analyze(_make_file_info("test_pdf_malicious.pdf"))
    autoopen = [i for i in result.indicators if i.name == "autoopen_action"]
    assert len(autoopen) == 2


def test_malicious_embedded_file():
    result = analyze(_make_file_info("test_pdf_malicious.pdf"))
    embedded = [i for i in result.indicators if i.name == "embedded_file"]
    assert len(embedded) == 2


def test_malicious_suspicious_object_stream():
    result = analyze(_make_file_info("test_pdf_malicious.pdf"))
    objstm = [i for i in result.indicators if i.name == "suspicious_object_stream"]
    assert len(objstm) == 1


def test_malicious_embedded_url():
    result = analyze(_make_file_info("test_pdf_malicious.pdf"))
    urls = [i for i in result.indicators if i.name == "embedded_url"]
    assert len(urls) == 1


def test_malicious_embedded_ip():
    result = analyze(_make_file_info("test_pdf_malicious.pdf"))
    ips = [i for i in result.indicators if i.name == "embedded_ip"]
    assert len(ips) == 1


def test_malicious_no_malformed_structure():
    result = analyze(_make_file_info("test_pdf_malicious.pdf"))
    malformed = [i for i in result.indicators if i.name == "malformed_structure"]
    assert len(malformed) == 0


def test_malicious_total_indicator_count():
    result = analyze(_make_file_info("test_pdf_malicious.pdf"))
    assert len(result.indicators) == 9


# --- Malformed PDF test cases ---------------------------------------------------


def test_malformed_structure_count():
    result = analyze(_make_file_info("test_pdf_malformed.pdf"))
    malformed = [i for i in result.indicators if i.name == "malformed_structure"]
    assert len(malformed) == 4


def test_malformed_structure_severity_is_low():
    result = analyze(_make_file_info("test_pdf_malformed.pdf"))
    malformed = [i for i in result.indicators if i.name == "malformed_structure"]
    assert all(i.severity == "low" for i in malformed)


def test_malformed_issue_messages():
    result = analyze(_make_file_info("test_pdf_malformed.pdf"))
    issues = {
        i.context["issue"] for i in result.indicators if i.name == "malformed_structure"
    }
    assert "missing or malformed %PDF- header" in issues
    assert "missing %%EOF marker near end of file" in issues
    assert "no trailer or cross-reference stream found" in issues
    assert "mismatched obj/endobj count (3 obj vs 2 endobj)" in issues


def test_malformed_no_content_indicators():
    result = analyze(_make_file_info("test_pdf_malformed.pdf"))
    content_indicators = [
        i for i in result.indicators if i.name != "malformed_structure"
    ]
    assert content_indicators == []


# --- Clean PDF test cases -------------------------------------------------------


def test_clean_pdf_no_indicators():
    result = analyze(_make_file_info("test_pdf_clean.pdf"))
    assert len(result.indicators) == 0


def test_clean_pdf_no_errors():
    result = analyze(_make_file_info("test_pdf_clean.pdf"))
    assert result.errors == []


# --- Common pdf files cases -----------------------------------------------------

SAMPLE_FILES = [
    "test_pdf_malicious.pdf",
    "test_pdf_malformed.pdf",
    "test_pdf_clean.pdf",
]


def test_analyzer_name():
    for filename in SAMPLE_FILES:
        result = analyze(_make_file_info(filename))
        assert result.analyzer == "pdf", f"Failed for {filename}"


def test_metadata_size_and_object_count():
    for filename in SAMPLE_FILES:
        result = analyze(_make_file_info(filename))
        assert result.metadata["size"] > 0, f"Failed for {filename}"
        assert "object_count" in result.metadata, f"Failed for {filename}"


def test_no_errors_on_valid_samples():
    for filename in SAMPLE_FILES:
        result = analyze(_make_file_info(filename))
        assert result.errors == [], f"Failed for {filename}"


# --- Test bad file cases --------------------------------------------------------


def test_empty_file(tmp_path):
    f = tmp_path / "empty.pdf"
    f.write_bytes(b"")

    file_info = FileInfo(
        file_id=1,
        filename="empty.pdf",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )

    result = analyze(file_info)

    malformed = [i for i in result.indicators if i.name == "malformed_structure"]
    assert len(malformed) == 3
    assert result.errors == []


def test_unreadable_file():
    file_info = FileInfo(
        file_id=1,
        filename="nonexistent.pdf",
        size=0,
        channel="test",
        author="test",
        path="/nonexistent/path/file.pdf",
    )

    result = analyze(file_info)

    assert len(result.errors) > 0
    assert result.indicators == []
