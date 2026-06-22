"""
Unit tests for analysis/generic_analyzer.py.
"""

from analysis.generic_analyzer import analyze, _extract_strings
from analysis.model import FileInfo
from pathlib import Path

# --- analyze test cases ---------------------------------------------------------

def test_url_detection(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"Visit http://evil.com/malware for more info")
    
    file_info = FileInfo(
        file_id=1,
        filename="sample.txt",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )
    
    result = analyze(file_info)
    
    urls = [i for i in result.indicators if i.name == "embedded_url"]
    assert len(urls) > 0

def test_ip_detection(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"Sent from 192.168.1.1")
    
    file_info = FileInfo(
        file_id=1,
        filename="sample.txt",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )
    
    result = analyze(file_info)
    
    ips = [i for i in result.indicators if i.name == "embedded_ip"]
    assert len(ips) > 0

def test_multiple_indicators():
    sample = Path("tests/samples/test_text.txt")
    
    file_info = FileInfo(
        file_id=1,
        filename="text_test.txt",
        size=sample.stat().st_size,
        channel="test",
        author="test",
        path=str(sample),
    )
    
    result = analyze(file_info)
    
    urls = [i for i in result.indicators if i.name == "embedded_url"]
    ips  = [i for i in result.indicators if i.name == "embedded_ip"]
    
    assert len(urls) == 5
    assert len(ips) == 5

def test_empty_file(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"")
    
    file_info = FileInfo(
        file_id=1,
        filename="sample.txt",
        size=f.stat().st_size,
        channel="test",
        author="test",
        path=str(f),
    )
    
    result = analyze(file_info)
    
    assert len(result.indicators) == 0
    assert result.errors == []

def test_unreadable_file():
    file_info = FileInfo(
        file_id=1,
        filename="nonexistent.txt",
        size=0,
        channel="test",
        author="test",
        path="/nonexistent/path/file.txt",
    )
    
    result = analyze(file_info)
    
    assert len(result.errors) > 0
    assert result.indicators == []

# --- _extract_strings test cases ------------------------------------------------

def test_extract_strings_min_length():
    data = b"abc" + b"\x00" + b"abcd"
    result = _extract_strings(data, min_length=4)
    
    assert "abc" not in result
    assert "abcd" in result

def test_extract_strings_non_printable():
    data = b"hello\x00world"
    result = _extract_strings(data, min_length=4)
    
    assert "hello" in result
    assert "world" in result
    assert "hello\x00world" not in result