import sys
from pathlib import Path
# Add project root to sys.path to resolve 'backend' imports when running main.py directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import settings
from backend.database import engine, Base
from backend.auth.router import router as auth_router
from backend.api.router import router as api_router
from backend.ai.router import router as ai_router

# Initialize Database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.APP_NAME,
    description="AI-powered Static Application Security Testing (SAST) and Secure Coding Analysis platform.",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None
)

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
def healthcheck():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "database": "connected",
        "ollama_url": settings.OLLAMA_API_URL
    }

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app", 
        host="0.0.0.0", 
        port=8000, 
        reload=True
    )
