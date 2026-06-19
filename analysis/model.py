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
    
@dataclass
class Indicator:
    name: str
    description: str
    severity: str
    context: dict
    
@dataclass
class AnalysisResult:
    analyzer: str          
    indicators: list[Indicator]
    metadata: dict
    errors: list[str]