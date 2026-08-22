from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime

# --- User Schemas ---
class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    username: str  # Can be username or email
    password: str

class UserResponse(UserBase):
    id: int
    name: Optional[str] = None
    role: str
    is_active: Optional[bool] = True
    created_at: datetime
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class ReportResponse(BaseModel):
    id: Optional[int] = None
    scan_id: int
    user_id: int
    report_type: str
    report_path: str
    status: str = "completed"
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class AdminStatsResponse(BaseModel):
    totalScans: int
    totalReports: int

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str
    email: Optional[str] = None

class TokenData(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    user_id: Optional[int] = None

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: Optional[str] = None
    password: Optional[str] = None

    @property
    def clean_password(self) -> str:
        return (self.new_password or self.password or "").strip()

class AdminUserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "user"

class AdminRoleUpdate(BaseModel):
    role: str

# --- Project Schemas ---
class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectCreate(ProjectBase):
    upload_type: str  # zip, folder, git, file

class ProjectResponse(ProjectBase):
    id: int
    upload_type: str = "file"
    language_detected: Optional[str] = None
    owner_id: int
    owner_username: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    latest_scan: Optional["ScanResponse"] = None

    model_config = ConfigDict(from_attributes=True)

# --- Scan Schemas ---
class ScanResponse(BaseModel):
    id: int
    project_id: int
    status: str = "pending"
    progress: int = 0
    trigger_type: Optional[str] = "manual"
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    created_at: datetime
    finished_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

# --- Vulnerability Schemas ---
class VulnerabilityResponse(BaseModel):
    id: int
    scan_id: int
    file_path: str = "main.py"
    line_number: Optional[int] = 1
    code_snippet: Optional[str] = ""
    severity: str = "INFO"
    category: str = "Security Vulnerability"
    message: str = ""
    tool_name: str = "Scanner Engine"
    status: str = "open"
    remediation: Optional[str] = None
    ai_explanation: Optional[str] = None
    ai_fix: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class VulnerabilityDetail(VulnerabilityResponse):
    pass


class VulnerabilityUpdate(BaseModel):
    status: str  # open, resolved, ignored, false_positive

# --- Chat Schemas ---
class ChatMessageBase(BaseModel):
    message: str

class ChatMessageCreate(ChatMessageBase):
    scan_id: int

class ChatMessageResponse(ChatMessageBase):
    id: Optional[int] = None
    scan_id: Optional[int] = None
    user_id: Optional[int] = None
    is_ai: bool = False
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class ChatQuery(BaseModel):
    vulnerability_id: Optional[int] = None
    message: str
    provider: Optional[str] = None
    model: Optional[str] = None

# --- Stats & Settings ---
class SeverityStats(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class ScanStats(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    severity_distribution: SeverityStats
    scans_history: List[ScanResponse]

class DashboardSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total_scans: int = 0
    total_vulnerabilities: int = 0
    fixed_vulnerabilities: int = 0
    security_score: int = 100
    recent_scans: List[ScanResponse] = []

class SecurityEventResponse(BaseModel):
    id: Optional[str] = None
    user_id: Optional[int] = None
    event_type: str
    description: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime

class AppSettings(BaseModel):
    openrouter_api_url: str = "https://openrouter.ai/api/v1"
    ollama_url: Optional[str] = "https://openrouter.ai/api/v1"
    default_model: str
    available_models: List[str]
    ai_provider: str
    openrouter_api_key_configured: bool = False
    openai_api_key_configured: bool = False
    gemini_api_key_configured: bool = False
    groq_api_key_configured: bool = False
    claude_api_key_configured: bool = False
    grok_api_key_configured: bool = False

class SettingsUpdate(BaseModel):
    openrouter_api_url: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    ollama_url: Optional[str] = None
    default_model: Optional[str] = None
    ai_provider: Optional[str] = None
    openai_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    groq_api_key: Optional[str] = None
    claude_api_key: Optional[str] = None
    grok_api_key: Optional[str] = None

class PasswordReset(BaseModel):
    username: str
    recovery_key: str
    new_password: str



