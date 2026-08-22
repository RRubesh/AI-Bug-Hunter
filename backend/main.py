import sys
import os
import types
from pathlib import Path

# Resolve sys.path so imports work both locally and on Vercel (Root Directory = backend)
current_dir = Path(__file__).resolve().parent
parent_dir = current_dir.parent

if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

# Alias 'backend' module package to current_dir if Vercel Root Directory is set to 'backend'
if not (parent_dir / "backend").exists() and (current_dir / "config.py").exists():
    backend_module = types.ModuleType("backend")
    backend_module.__path__ = [str(current_dir)]
    sys.modules["backend"] = backend_module

# Remove shadowing database.py file if present so backend.database package directory is used
db_file = current_dir / "database.py"
if db_file.exists():
    try:
        os.remove(db_file)
    except Exception:
        pass

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import settings
from backend.database import engine, Base, SessionLocal, is_mongo_connected
from backend.models import User
from backend.auth.jwt import get_password_hash, verify_password
from backend.auth.router import router as auth_router
from backend.api.router import router as api_router
from backend.ai.router import router as ai_router

import shutil
from backend.database.mongodb import mongo_manager
from backend.ai.openrouter_client import openrouter_client

# Initialize Database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    description="AI-powered Static Application Security Testing (SAST) and Secure Coding Analysis platform.",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None
)

@app.on_event("startup")
def startup_event():
    print(f"[Startup]: Initializing {settings.APP_NAME} platform engines...")

    # Ensure default admin account exists
    try:
        db = SessionLocal()
        admin_user = db.query(User).filter((User.username == "rubesh") | (User.email == "rubesh@aibughunter.local")).first()
        if not admin_user:
            admin_user = User(
                username="rubesh",
                email="rubesh@aibughunter.local",
                hashed_password=get_password_hash("admin123"),
                role="admin",
                is_active=True
            )
            db.add(admin_user)
            db.commit()
        else:
            if not verify_password("admin123", admin_user.hashed_password):
                admin_user.hashed_password = get_password_hash("admin123")
                admin_user.role = "admin"
                admin_user.is_active = True
                db.commit()
        db.close()
    except Exception as e:
        print("[Admin Seed Exception]:", e)

    # Verify MongoDB Atlas connection and indexes
    try:
        connected = mongo_manager.connect()
        if connected:
            mongo_manager.log_audit_event(action="platform_startup", resource="system", details={"description": "AI Bug Hunter backend started successfully."})
        else:
            print("[Startup Notice]: Running with SQLite local storage fallback (MONGODB_URI unconfigured or unreachable).")
    except Exception as me:
        print("[MongoDB Startup Notice]:", me)

@app.on_event("shutdown")
def shutdown_event():
    print(f"[Shutdown]: Gracefully shutting down {settings.APP_NAME}...")
    try:
        mongo_manager.disconnect()
    except Exception as me:
        print("[MongoDB Shutdown Notice]:", me)


# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r".*",  # Supports wildcard origins with credentials across domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(auth_router, prefix="/api")
app.include_router(api_router)
app.include_router(ai_router, prefix="/api")

@app.get("/health")
@app.get("/api/health")
async def healthcheck():
    mongo_status = "connected" if mongo_manager.is_connected() else ("configured" if settings.MONGODB_URL else "not_configured")
    
    # Check OpenRouter AI connection / readiness
    ai_status = "configured" if (settings.OPENROUTER_API_KEY or settings.OPENAI_API_KEY or settings.GEMINI_API_KEY or settings.GROQ_API_KEY) else "ready"
    try:
        models = await openrouter_client.list_models()
        if models:
            ai_status = "connected"
    except Exception:
        pass

    # Check availability of scanner executables
    gitleaks_avail = shutil.which("gitleaks") is not None
    bandit_avail = shutil.which("bandit") is not None
    semgrep_avail = shutil.which("semgrep") is not None
    dependency_avail = True  # Internal fallback runner

    return {
        "api": "healthy",
        "app": settings.APP_NAME,
        "mongodb": mongo_status,
        "ai_engine": ai_status,
        "openrouter": ai_status,
        "scanners": {
            "gitleaks": gitleaks_avail,
            "bandit": bandit_avail,
            "semgrep": semgrep_avail,
            "dependency_check": dependency_avail
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True
    )

