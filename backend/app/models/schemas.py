import uuid


from datetime import datetime


from enum import Enum

from typing import Any, Dict, List, Optional


from pydantic import AnyHttpUrl, BaseModel, Field


class FileType(str, Enum):

    EXE = "exe"

    PDF = "pdf"


class MalwareCategory(str, Enum):

    RANSOMWARE = "ransomware"

    TROJAN = "trojan"

    WORM = "worm"

    VIRUS = "virus"

    ADWARE = "adware"

    SPYWARE = "spyware"

    ROOTKIT = "rootkit"

    BOTNET = "botnet"

    BACKDOOR = "backdoor"

    CLEAN = "clean"

    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):

    HIGH = "high"

    MEDIUM = "medium"

    LOW = "low"

    CLEAN = "clean"

    UNKNOWN = "unknown"


# File Upload and Analysis Schemas

class FileUploadResponse(BaseModel):

    file_id: str

    filename: str

    file_type: FileType

    file_size: int

    upload_time: datetime

    status: str = "pending"

    task_id: Optional[str] = None


class DynamicBehavior(BaseModel):

    type: str

    subtype: str

    severity: SeverityLevel

    description: str

    details: Dict[str, Any]


class NetworkConnection(BaseModel):

    local_address: str

    local_port: int

    remote_address: Optional[str] = None

    remote_port: Optional[int] = None

    status: str

    pid: Optional[int] = None


class ProcessActivity(BaseModel):

    pid: int

    name: str

    command_line: Optional[List[str]] = None

    username: Optional[str] = None


class FileOperation(BaseModel):

    path: str

    operation: str

    timestamp: Optional[datetime] = None

    process_id: Optional[int] = None


class RegistryOperation(BaseModel):

    key: str

    operation: str

    value: Optional[str] = None

    timestamp: Optional[datetime] = None

    process_id: Optional[int] = None


class DynamicAnalysisDetails(BaseModel):

    network_activity: List[NetworkConnection] = []

    process_activity: List[ProcessActivity] = []

    file_system_activity: List[FileOperation] = []

    registry_activity: List[RegistryOperation] = []

    suspicious_behaviors: List[DynamicBehavior] = []

    execution_time: float

    exit_code: Optional[int] = None

class FileInfo(BaseModel):

    file_id: str

    original_filename: str

    file_path: str

    file_type: FileType

    file_size: int

    upload_time: datetime

    md5: str

    sha1: str

    sha256: str

    mime_type: str


class Indicator(BaseModel):

    name: str

    description: str

    severity: SeverityLevel

    confidence: float


class ExeAnalysisDetails(BaseModel):

    file_type: str = "executable"

    architecture: Optional[str] = None

    is_packed: Optional[bool] = None

    packer_type: Optional[str] = None

    imports: List[str] = []

    exports: List[str] = []

    sections: List[Dict[str, Any]] = []

    libraries: List[str] = []

    entry_point: Optional[str] = None

    compile_time: Optional[datetime] = None

    digital_signature: Optional[Dict[str, Any]] = None

    strings_of_interest: List[str] = []

    resources: List[Dict[str, Any]] = []

    pe_characteristics: Optional[Dict[str, Any]] = None

    is_dll: Optional[bool] = None

    is_driver: Optional[bool] = None

    is_exe: Optional[bool] = None

    subsystem: Optional[str] = None


class PdfAnalysisDetails(BaseModel):

    file_type: str = "pdf"

    version: Optional[str] = None

    page_count: Optional[int] = None

    has_javascript: bool = False

    javascript_code: Optional[List[str]] = None

    has_forms: bool = False

    has_embedded_files: bool = False

    embedded_files: List[Dict[str, Any]] = []

    has_auto_action: bool = False

    auto_actions: List[Dict[str, Any]] = []

    has_suspicious_objects: bool = False

    suspicious_objects: List[Dict[str, Any]] = []

    has_encryption: bool = False

    has_obfuscation: bool = False

    metadata: Optional[Dict[str, Any]] = None

    acroform_fields: List[Dict[str, Any]] = []

    xfa_forms: List[Dict[str, Any]] = []

    urls: List[str] = []


class AnalysisDetails(BaseModel):

    file_info: FileInfo

    malware_score: float

    malware_category: MalwareCategory

    severity: SeverityLevel

    confidence: float

    analysis_time: datetime

    indicators: List[Indicator] = []

    exe_details: Optional[ExeAnalysisDetails] = None

    pdf_details: Optional[PdfAnalysisDetails] = None
    dynamic_analysis: Optional[DynamicAnalysisDetails] = None
    network_indicators: List[Dict[str, Any]] = []

    yara_matches: List[Dict[str, Any]] = []

    behavioral_indicators: List[Dict[str, Any]] = []

    static_analysis_summary: str

    malware_family: Optional[str] = None

    recommendation: str


class AnalysisStatusResponse(BaseModel):

    file_id: str

    task_id: str

    status: str

    progress: float = 0.0

    estimated_completion_time: Optional[datetime] = None

    result_url: Optional[AnyHttpUrl] = None


class AnalysisResult(BaseModel):

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    file_id: str

    task_id: str

    status: str

    completed_at: Optional[datetime] = None

    details: Optional[AnalysisDetails] = None

    report_path: Optional[str] = None


class AnalysisRequest(BaseModel):

    file_id: str

    analysis_type: str = "full"  # full, static, dynamic

    priority: str = "normal"

    callback_url: Optional[AnyHttpUrl] = None


class HealthCheck(BaseModel):

    status: str

    version: str

    timestamp: datetime = Field(default_factory=datetime.utcnow)