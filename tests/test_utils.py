"""
Unit tests for analysis/utils.py.
"""

from analysis.utils import defang, extract_urls, extract_ips, compute_hashes, safe_filename, format_size

# --- defang test cases ----------------------------------------------------------

def test_defang_http():
    assert defang("http://evil.com") == "hxxp://evil[.]com"

def test_defang_https():
    assert defang("https://evil.com") == "hxxps://evil[.]com"

def test_defang_dot():
    assert defang("evil.com") == "evil[.]com"

def test_defang_at():
    assert defang("user@evil.com") == "user[at]evil[.]com"

def test_defang_full_url():
    assert defang("https://user@evil.com/path") == "hxxps://user[at]evil[.]com/path"

def test_defang_empty():
    assert defang("") == ""

# --- extract_urls test cases ----------------------------------------------------

def test_extract_urls_http():
    assert extract_urls("Check out http://evil.com") == ["http://evil.com"]

def test_extract_urls_https():
    assert extract_urls("Check out https://evil.com") == ["https://evil.com"]

def test_extract_urls_multiple():
    assert extract_urls("Check out http://evil.com and https://good.com") == ["http://evil.com", "https://good.com"]

def test_extract_urls_none():
    assert extract_urls("No URLs here!") == []

def test_extract_urls_too_short():
    assert extract_urls("http://abc") == []

def test_extract_urls_minimum():
    assert extract_urls("http://x.io") == ["http://x.io"]

# --- extract_ips test cases -----------------------------------------------------

def test_extract_ips_basic():
    assert extract_ips("IP: 192.168.1.1") == ["192.168.1.1"]

def test_extract_ips_multiple():
    assert extract_ips("IPs: 192.168.1.1, 10.0.0.1") == ["192.168.1.1", "10.0.0.1"]

def test_extract_ips_none():
    assert extract_ips("No IPs here!") == []

# --- compute_hashes test cases --------------------------------------------------

def test_compute_hashes_keys(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"hello")
    assert set(compute_hashes(str(f)).keys()) == {"sha256", "sha1", "md5"}

def test_compute_hashes_values(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"hello")
    hashes = compute_hashes(str(f))
    assert all(isinstance(hashes[k], str) and len(hashes[k]) > 0 for k in hashes)

def test_compute_hashes_deterministic(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_bytes(b"hello")
    assert compute_hashes(str(f)) == compute_hashes(str(f))

# --- safe_filename test cases ---------------------------------------------------

def test_safe_filename_basic():
    assert safe_filename(123, "file.txt") == "123_file.txt"

def test_safe_filename_special_chars():
    assert safe_filename(123, "fi<>le.txt") == "123_fi__le.txt"

# --- format_size test cases -----------------------------------------------------

def test_format_size_bytes():
    assert format_size(512) == "512 B"

def test_format_size_kb():
    assert format_size(1024) == "1.0 KB"

def test_format_size_mb():
    assert format_size(1024 * 1024) == "1.0 MB"