import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.database import Base

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="developer")  # admin, developer, paid
    created_at = Column(DateTime, default=utcnow)

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    file_path = Column(String, nullable=True)  # path to uploaded zip/folder/file
    upload_type = Column(String, nullable=False)  # zip, folder, git, file
    language_detected = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")

    @property
    def owner_username(self):
        return self.owner.username if self.owner else None

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    status = Column(String, default="pending")  # pending, running, completed, failed
    progress = Column(Integer, default=0)       # 0 to 100
    trigger_type = Column(String, default="manual")  # manual, scheduled, webhook
    
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=utcnow)
    finished_at = Column(DateTime, nullable=True)
    
    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    chat_messages = relationship("ChatMessage", back_populates="scan", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    
    severity = Column(String, nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category = Column(String, nullable=False)  # SQLi, XSS, Cmd Injection, Secret, Vulnerable Dependency, etc.
    message = Column(Text, nullable=False)
    tool_name = Column(String, nullable=False)  # Gitleaks, Bandit, Semgrep, Trivy, Fallback
    
    remediation = Column(Text, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    ai_fix = Column(Text, nullable=True)
    status = Column(String, default="open")  # open, resolved, ignored, false_positive
    
    created_at = Column(DateTime, default=utcnow)

    scan = relationship("Scan", back_populates="vulnerabilities")

class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    
    message = Column(Text, nullable=False)
    is_ai = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    scan = relationship("Scan", back_populates="chat_messages")
