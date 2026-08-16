import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

class Settings(BaseSettings):
    APP_NAME: str = "AI Bug Hunter"
    DEBUG: bool = True
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-change-in-production-1234567890")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    
    # Directories
    BASE_DIR: Path = Path(__file__).resolve().parent
    UPLOAD_DIR: Path = BASE_DIR / "uploads"
    REPORT_DIR: Path = BASE_DIR / "reports"
    
    # Database
    # Use SQLite by default for zero-config run, fallback if PostgreSQL fails
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/ai_bug_hunter.db")
    MONGODB_URL: str = os.getenv("MONGODB_URL", "")
    MONGODB_URI: str = os.getenv("MONGODB_URI", "")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "ai_bug_hunter")
    MONGODB_DATABASE: str = os.getenv("MONGODB_DATABASE", "ai_bug_hunter")
    
    # AI Provider Configurations
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_API_BASE_URL: str = os.getenv("OPENROUTER_API_BASE_URL", "https://openrouter.ai/api/v1")
    DEFAULT_LLM_MODEL: str = os.getenv("DEFAULT_LLM_MODEL", "deepseek/deepseek-chat")
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "openrouter")
    
    # Direct Provider API Keys (Optional)
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    CLAUDE_API_KEY: str = os.getenv("CLAUDE_API_KEY", "")
    GROK_API_KEY: str = os.getenv("GROK_API_KEY", "")

    # Legacy compatibility
    OLLAMA_API_URL: str = os.getenv("OPENROUTER_API_BASE_URL", "https://openrouter.ai/api/v1")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

# Detect Vercel serverless environment
is_vercel = bool(os.getenv("VERCEL") or os.getenv("VERCEL_ENV") or os.getenv("NOW_BUILDER"))

settings = Settings()
if settings.AI_PROVIDER.lower() == "ollama":
    settings.AI_PROVIDER = "openrouter"

if is_vercel:
    temp_dir = Path("/tmp")
    settings.UPLOAD_DIR = temp_dir / "uploads"
    settings.REPORT_DIR = temp_dir / "reports"
    if settings.DATABASE_URL.startswith("sqlite") and "/tmp/" not in settings.DATABASE_URL:
        settings.DATABASE_URL = "sqlite:////tmp/ai_bug_hunter.db"

try:
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    os.makedirs(settings.REPORT_DIR, exist_ok=True)
except Exception as err:
    print(f"[Config Directory Notice]: {err}")

# Synchronize MONGODB_URL and MONGODB_URI
if not settings.MONGODB_URL and settings.MONGODB_URI:
    settings.MONGODB_URL = settings.MONGODB_URI
if not settings.MONGODB_DB_NAME and settings.MONGODB_DATABASE:
    settings.MONGODB_DB_NAME = settings.MONGODB_DATABASE

# If DATABASE_URL is set to a MongoDB Atlas URL, extract it for MONGODB_URL and fallback DATABASE_URL to SQLite for SQLAlchemy
if settings.DATABASE_URL.startswith("mongodb://") or settings.DATABASE_URL.startswith("mongodb+srv://"):
    if not settings.MONGODB_URL:
        settings.MONGODB_URL = settings.DATABASE_URL
    default_sqlite_path = "/tmp/ai_bug_hunter.db" if is_vercel else f"{settings.BASE_DIR}/ai_bug_hunter.db"
    settings.DATABASE_URL = f"sqlite:///{default_sqlite_path}"
