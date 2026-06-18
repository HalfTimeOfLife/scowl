from dataclasses import dataclass

@dataclass
class FileInfo:
    file_id: int
    filename: str
    size: int
    channel: str
    author: str
    path: str = ""
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    content_type: str = ""