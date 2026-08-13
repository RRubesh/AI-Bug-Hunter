import sys
import os
from pathlib import Path
# Add project root to sys.path to resolve 'backend' imports when running main.py directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Remove shadowing database.py file if present so backend.database package directory is used
db_file = Path(__file__).resolve().parent / "database.py"
if db_file.exists():
    try:
        os.remove(db_file)
    except Exception:
        pass

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import settings
from backend.database import engine, Base, is_mongo_connected
from backend.auth.router import router as auth_router
from backend.api.router import router as api_router
from backend.ai.router import router as ai_router

import shutil
from backend.database.mongodb import mongo_manager
from backend.ai.ollama_client import ollama_client

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
    print("[Startup]: Initializing AI Bug Hunter platform engines...")
    try:
        src_logo = r"C:\Users\91904\.gemini\antigravity-ide\brain\afe98b21-0dc6-471d-8c96-51cc40bfc616\media__1786547982528.jpg"
        dst_logo1 = r"c:\Users\91904\OneDrive\Music\Documents\AI Bug Hunter\frontend\src\assets\logo.jpg"
        dst_logo2 = r"c:\Users\91904\OneDrive\Music\Documents\AI Bug Hunter\frontend\public\logo.jpg"
        icon_dst = r"c:\Users\91904\OneDrive\Music\Documents\AI Bug Hunter\frontend\src\assets\logo-icon.jpg"
        if os.path.exists(src_logo):
            try:
                shutil.copyfile(src_logo, dst_logo1)
                shutil.copyfile(src_logo, dst_logo2)
                try:
                    from PIL import Image
                    im = Image.open(src_logo)
                    w, h = im.size
                    crop_box = (int(w * 0.15), int(h * 0.02), int(w * 0.85), int(h * 0.65))
                    icon_im = im.crop(crop_box)
                    icon_im.save(icon_dst, quality=95)
                    icon_public = r"c:\Users\91904\OneDrive\Music\Documents\AI Bug Hunter\frontend\public\logo-icon.jpg"
                    icon_im.save(icon_public, quality=95)
                    print("[Logo Update]: Created crisp logo-icon.jpg successfully!")
                except Exception as pe:
                    print("[PIL Crop Notice]:", pe)
                print("[Logo Update]: Copied new logo image to frontend assets successfully!")
            except Exception as e:
                print("[Logo Update Error]:", e)
    except Exception as se:
        print("[Startup File Notice]:", se)

    # Verify MongoDB Atlas connection and indexes
    try:
        connected = mongo_manager.connect()
        if connected:
            mongo_manager.log_security_event("platform_startup", "AI Bug Hunter backend started successfully.")
        else:
            print("[Startup Notice]: Running with SQLite local storage fallback (MONGODB_URI unconfigured or unreachable).")
    except Exception as me:
        print("[MongoDB Startup Notice]:", me)


# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For local development ease, restrict in production config
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
    
    # Check Ollama connection
    ollama_connected = False
    try:
        models = await ollama_client.list_models()
        ollama_connected = bool(models)
    except Exception:
        ollama_connected = False

    # Check availability of scanner executables
    gitleaks_avail = shutil.which("gitleaks") is not None
    bandit_avail = shutil.which("bandit") is not None
    semgrep_avail = shutil.which("semgrep") is not None
    dependency_avail = True  # Internal fallback runner

    return {
        "api": "healthy",
        "app": settings.APP_NAME,
        "mongodb": mongo_status,
        "ollama": "connected" if ollama_connected else "disconnected",
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

