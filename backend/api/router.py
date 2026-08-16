import os
import shutil
import uuid
import subprocess
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status, BackgroundTasks
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy.orm import Session
from backend.database import get_db, SessionLocal, is_mongo_connected, get_mongo_db
from backend.database.mongodb import mongo_manager
from backend.models import Project, Scan, Vulnerability, User
from backend.schemas import (
    ProjectResponse, ProjectCreate, ScanResponse, VulnerabilityResponse, 
    VulnerabilityDetail, VulnerabilityUpdate, ScanStats, SeverityStats, 
    DashboardSummary, AppSettings, UserResponse, UserCreate, SettingsUpdate
)
from backend.auth.jwt import get_current_user, get_current_admin, get_password_hash
from backend.config import settings
from backend.scanner.engine import start_background_scan
from backend.reports.pdf_gen import generate_pdf_report
from backend.reports.html_gen import generate_html_report
from backend.ai.openrouter_client import openrouter_client, ollama_client
from typing import List, Optional
from pathlib import Path

router = APIRouter(prefix="/api", tags=["Code Security Scans"])

# --- PROJECT MANAGEMENT ---

def detect_pasted_code_filename(code: str) -> str:
    import re
    code_stripped = code.strip()
    if code_stripped.startswith("<?php") or "<?php" in code:
        return "main.php"
    if "package main" in code or ("import (" in code and "fmt" in code):
        return "main.go"
    if "using System;" in code or "using System.Data" in code:
        return "Program.cs"
    if "fn main()" in code or "use std::" in code:
        return "main.rs"
    if "public class " in code or "import java." in code:
        match = re.search(r"public\s+class\s+(\w+)", code)
        if match:
            return f"{match.group(1)}.java"
        return "Main.java"
    if "#include <" in code or "int main(" in code:
        if "std::" in code or "iostream" in code or "using namespace std" in code:
            return "main.cpp"
        return "main.c"
    
    # Differentiate Python vs JavaScript / TypeScript
    if "const " in code or "let " in code or "function " in code or "require(" in code:
        if "interface " in code or "type " in code or "as " in code:
            return "index.ts"
        return "index.js"
        
    if "import " in code or "def " in code or "class " in code or "print(" in code or "#" in code:
        if "const " in code or "let " in code or "function " in code or "require(" in code:
            if "import " in code and (":" in code or "as " in code):
                return "index.ts"
            return "index.js"
        return "main.py"
        
    return "main.py"

@router.post("/projects", response_model=ProjectResponse)
def create_project(
    name: str = Form(...),
    description: Optional[str] = Form(None),
    upload_type: str = Form(...),  # zip, folder, git, file
    git_url: Optional[str] = Form(None),
    pasted_code: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    project_id_str = str(uuid.uuid4())
    project_dir = settings.UPLOAD_DIR / project_id_str
    project_dir.mkdir(parents=True, exist_ok=True)
    
    file_path = str(project_dir)

    # 1. Handle single file paste or direct source file upload
    if upload_type == "file":
        if file:
            filename = file.filename or "main.py"
            dest_file = project_dir / filename
            with open(dest_file, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
        elif pasted_code:
            filename = detect_pasted_code_filename(pasted_code)
            dest_file = project_dir / filename
            with open(dest_file, "w", encoding="utf-8") as f:
                f.write(pasted_code)
        else:
            raise HTTPException(status_code=400, detail="Pasted code or source file cannot be empty")
            
    # 2. Handle ZIP or direct file upload
    elif upload_type == "zip":
        if not file:
            raise HTTPException(status_code=400, detail="Source file or ZIP archive upload is required")
        
        orig_filename = file.filename or "upload.zip"
        saved_file_path = project_dir / orig_filename
        with open(saved_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Check if the uploaded file is indeed a ZIP archive
        import zipfile
        if zipfile.is_zipfile(saved_file_path):
            try:
                ignored_dirs = {"node_modules", ".git", "__pycache__", "venv", ".venv", ".next", "dist", "build"}
                with zipfile.ZipFile(saved_file_path, 'r') as zip_ref:
                    for member in zip_ref.infolist():
                        filename = Path(member.filename)
                        if ".." in filename.parts or filename.is_absolute():
                            continue
                        parts = {p.lower() for p in filename.parts}
                        if parts & ignored_dirs:
                            continue
                        zip_ref.extract(member, project_dir)
                # Remove zip archive after successful extraction
                saved_file_path.unlink(missing_ok=True)
            except Exception as e:
                shutil.rmtree(project_dir, ignore_errors=True)
                raise HTTPException(status_code=400, detail=f"Failed to extract ZIP archive: {str(e)}")
        else:
            # It's a single source code file uploaded under the file/zip tab (e.g. main.py, app.js)
            # It is already saved at saved_file_path!
            pass

    # 3. Handle Git Repository
    elif upload_type == "git":
        if not git_url:
            raise HTTPException(status_code=400, detail="Git Repository URL is required")
        try:
            # Execute git clone
            cmd = ["git", "clone", "--depth", "1", git_url, str(project_dir)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode != 0:
                raise Exception(res.stderr)
        except Exception as e:
            shutil.rmtree(project_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"Failed to clone Git Repository: {str(e)}")

    # 4. Handle Website/URL Link Ingestion
    elif upload_type == "url":
        if not git_url:
            raise HTTPException(status_code=400, detail="Website/URL link is required")
        if not (git_url.startswith("http://") or git_url.startswith("https://")):
            raise HTTPException(status_code=400, detail="Invalid URL format. Must start with http:// or https://")
        
        try:
            import httpx
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            
            content = None
            content_type = ""
            
            try:
                # 1. Try fetching with httpx
                with httpx.Client(follow_redirects=True, timeout=30.0) as client:
                    response = client.get(git_url, headers=headers)
                    if response.status_code == 200:
                        content = response.content
                        content_type = response.headers.get("content-type", "").lower()
                    else:
                        raise Exception(f"Server returned status code {response.status_code}")
            except Exception as httpx_err:
                # 2. Fall back to system curl execution if blocked/403
                try:
                    import tempfile
                    
                    with tempfile.TemporaryDirectory() as tmp_dir:
                        out_file = Path(tmp_dir) / "content.bin"
                        hdr_file = Path(tmp_dir) / "headers.txt"
                        
                        cmd = [
                            "curl",
                            "-sL",
                            "-A", headers["User-Agent"],
                            "-D", str(hdr_file),
                            "-o", str(out_file),
                            git_url
                        ]
                        subprocess.run(cmd, capture_output=True, text=True, timeout=30.0)
                        
                        if out_file.exists() and out_file.stat().st_size > 0:
                            with open(out_file, "rb") as f:
                                content = f.read()
                            
                            if hdr_file.exists():
                                with open(hdr_file, "r", encoding="utf-8", errors="ignore") as f:
                                    for line in f:
                                        if line.lower().startswith("content-type:"):
                                            content_type = line.split(":", 1)[1].strip().lower()
                                            break
                        else:
                            raise Exception(f"curl download failed: {httpx_err}")
                except Exception as curl_err:
                    raise Exception(f"Failed download using both HTTP client and curl fallback. Error: {httpx_err} / Curl error: {curl_err}")
            
            # Check if it's a zip file: content-type header or ends with .zip
            is_zip = "zip" in content_type or git_url.split("?")[0].lower().endswith(".zip")
            
            if is_zip:
                zip_path = project_dir / "download.zip"
                with open(zip_path, "wb") as buffer:
                    buffer.write(content)
                
                # Extract zip
                import zipfile
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                        for member in zip_ref.infolist():
                            filename = Path(member.filename)
                            if ".." in filename.parts or filename.is_absolute():
                                continue
                            zip_ref.extract(member, project_dir)
                    zip_path.unlink()
                except Exception as e:
                    raise Exception(f"Failed to extract ZIP archive: {str(e)}")
            else:
                # It's a single file (like raw code, html, text, etc.)
                # Let's extract the file name from URL path or headers
                from urllib.parse import urlparse
                parsed_url = urlparse(git_url)
                path_name = os.path.basename(parsed_url.path)
                
                # Ensure filename is safe and has a valid code extension, default to index.html or main.py
                valid_extensions = (".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".c", ".cpp", ".h", ".hpp", ".php", ".html", ".css", ".json", ".txt")
                filename = path_name if path_name and path_name.lower().endswith(valid_extensions) else None
                
                if not filename:
                    if "html" in content_type:
                        filename = "index.html"
                    else:
                        filename = "main.py"
                
                dest_file = project_dir / filename
                with open(dest_file, "wb") as f:
                    f.write(content)
                    
        except Exception as e:
            if project_dir.exists():
                shutil.rmtree(project_dir)
            raise HTTPException(status_code=400, detail=f"Failed to download from URL: {str(e)}")
            
    else:
        raise HTTPException(status_code=400, detail="Invalid upload_type. Must be file, zip, git, or url")

    new_project = Project(
        name=name,
        description=description,
        file_path=file_path,
        upload_type=upload_type,
        owner_id=current_user.id
    )
    db.add(new_project)
    db.commit()
    db.refresh(new_project)

    try:
        from backend.database import get_mongo_db, is_mongo_connected
        if is_mongo_connected():
            mongo_db = get_mongo_db()
            if mongo_db is not None:
                mongo_db.projects.update_one(
                    {"project_id": new_project.id},
                    {"$set": {
                        "project_id": new_project.id,
                        "name": new_project.name,
                        "description": new_project.description,
                        "upload_type": new_project.upload_type,
                        "owner_id": new_project.owner_id,
                        "created_at": new_project.created_at
                    }},
                    upsert=True
                )
    except Exception:
        pass

    return new_project

@router.get("/projects", response_model=List[ProjectResponse])
def list_projects(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == "admin":
        return db.query(Project).all()
    return db.query(Project).filter(Project.owner_id == current_user.id).all()

@router.get("/projects/{project_id}", response_model=ProjectResponse)
def get_project(project_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this project")
    return project

@router.delete("/projects/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(project_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to delete this project")
    
    # Delete uploaded directory
    if project.file_path and os.path.exists(project.file_path):
        try:
            shutil.rmtree(project.file_path)
        except Exception:
            pass
            
    db.delete(project)
    db.commit()
    return JSONResponse(status_code=status.HTTP_200_OK, content={"message": "Project deleted successfully"})

# --- SCAN MANAGEMENT ---

@router.post("/scans/{project_id}", response_model=ScanResponse)
def trigger_scan(project_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    # Create new scan record
    new_scan = Scan(
        project_id=project.id,
        status="pending",
        progress=0
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Launch scanning asynchronously (passing SessionLocal factory to avoid thread collisions)
    start_background_scan(SessionLocal, new_scan.id, project.file_path or "")

    return new_scan

@router.get("/scans/project/{project_id}", response_model=List[ScanResponse])
def get_project_scans(project_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    return db.query(Scan).filter(Scan.project_id == project_id).order_by(Scan.created_at.desc()).all()

@router.get("/scans", response_model=List[ScanResponse])
def list_scans(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == "admin":
        return db.query(Scan).order_by(Scan.created_at.desc()).all()
    user_projects = db.query(Project).filter(Project.owner_id == current_user.id).all()
    project_ids = [p.id for p in user_projects]
    if not project_ids:
        return []
    return db.query(Scan).filter(Scan.project_id.in_(project_ids)).order_by(Scan.created_at.desc()).all()

@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan session not found")
    if scan.project and scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")

    return scan

@router.post("/scans/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(scan_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan session not found")
    if scan.project and scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    scan.status = "cancelled"
    db.commit()
    db.refresh(scan)

    try:
        if is_mongo_connected():
            mongo_db = get_mongo_db()
            if mongo_db is not None:
                mongo_db.scans.update_one({"scan_id": scan.id}, {"$set": {"status": "cancelled"}})
    except Exception:
        pass

    mongo_manager.log_security_event(
        event_type="scan_cancelled",
        description=f"Scan #{scan.id} was cancelled by user.",
        user_id=current_user.id
    )

    return scan

@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan session not found")
    if scan.project and scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    db.delete(scan)
    db.commit()

    try:
        if is_mongo_connected():
            mongo_db = get_mongo_db()
            if mongo_db is not None:
                mongo_db.scans.delete_one({"scan_id": scan_id})
                mongo_db.vulnerabilities.delete_many({"scan_id": scan_id})
                mongo_db.scanner_results.delete_many({"scan_id": scan_id})
                mongo_db.ai_analysis.delete_many({"scan_id": scan_id})
    except Exception:
        pass

    return {"message": "Scan session deleted successfully"}

# --- VULNERABILITIES LIST & FILES VIEW ---

@router.get("/scans/{scan_id}/vulnerabilities", response_model=List[VulnerabilityResponse])
def get_vulnerabilities(scan_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan session not found")
    if scan.project and scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")

    return db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()

@router.get("/vulnerabilities", response_model=List[VulnerabilityResponse])
def list_all_vulnerabilities(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == "admin":
        return db.query(Vulnerability).all()
    user_projects = db.query(Project).filter(Project.owner_id == current_user.id).all()
    project_ids = [p.id for p in user_projects]
    user_scans = db.query(Scan).filter(Scan.project_id.in_(project_ids)).all() if project_ids else []
    scan_ids = [s.id for s in user_scans]
    if not scan_ids:
        return []
    return db.query(Vulnerability).filter(Vulnerability.scan_id.in_(scan_ids)).all()

@router.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityDetail)
def get_vulnerability_detail(vuln_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    if vuln.scan and vuln.scan.project and vuln.scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    return vuln

@router.patch("/vulnerabilities/{vuln_id}", response_model=VulnerabilityDetail)
def update_vulnerability_status(
    vuln_id: int,
    vuln_update: VulnerabilityUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if vuln_update.status not in ("open", "resolved", "ignored", "false_positive"):
        raise HTTPException(status_code=400, detail="Invalid status type. Must be open, resolved, ignored, or false_positive")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability finding not found")
    if vuln.scan and vuln.scan.project and vuln.scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    vuln.status = vuln_update.status
    db.commit()
    db.refresh(vuln)

    try:
        if is_mongo_connected():
            mongo_db = get_mongo_db()
            if mongo_db is not None:
                mongo_db.vulnerabilities.update_one(
                    {"vulnerability_id": vuln.id},
                    {"$set": {"status": vuln.status}}
                )
    except Exception:
        pass

    mongo_manager.log_security_event(
        event_type="vulnerability_status_updated",
        description=f"Vulnerability #{vuln.id} status changed to {vuln.status}",
        user_id=current_user.id
    )

    return vuln

@router.get("/projects/{project_id}/file-content")
def get_project_file_content(project_id: int, path: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to access this project")

    if not project.file_path:
        raise HTTPException(status_code=404, detail="Project source path not found")

    base_path = Path(project.file_path).resolve()
    target_file = None

    if base_path.is_file():
        # If the project is a single file upload
        if path in (base_path.name, "", os.path.basename(path)):
            target_file = base_path
        else:
            cand = (base_path.parent / path).resolve()
            if cand.exists() and cand.is_file():
                target_file = cand
    else:
        # If the project is a folder/zip extraction
        cand = (base_path / path).resolve()
        if cand.exists() and cand.is_file():
            try:
                if cand.is_relative_to(base_path):
                    target_file = cand
            except Exception:
                target_file = cand
        else:
            # Fallback search by filename
            filename = Path(path).name
            for root, _, files in os.walk(base_path):
                if filename in files:
                    target_file = Path(root) / filename
                    break

    if not target_file or not target_file.exists() or not target_file.is_file():
        raise HTTPException(status_code=404, detail=f"File '{path}' not found in project")
         
    try:
        with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return {"content": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {str(e)}")

# --- REPORTS DOWNLOADS ---

@router.get("/scans/{scan_id}/report/{report_format}")
def download_report(scan_id: int, report_format: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.project and scan.project.owner_id != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="Scan has not completed yet")

    vulnerabilities = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    project = scan.project

    if report_format == "json":
        # Format JSON structure
        data = {
            "project_name": project.name if project else "Project",
            "language": project.language_detected if project else "unknown",
            "scan_id": scan.id,
            "critical_count": scan.critical_count,
            "high_count": scan.high_count,
            "medium_count": scan.medium_count,
            "low_count": scan.low_count,
            "total_vulnerabilities": scan.total_vulnerabilities,
            "vulnerabilities": [
                {
                    "category": v.category,
                    "severity": v.severity,
                    "message": v.message,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "code_snippet": v.code_snippet,
                    "remediation": v.remediation,
                    "ai_explanation": v.ai_explanation,
                    "ai_fix": v.ai_fix
                } for v in vulnerabilities
            ]
        }
        proj_name = project.name if project else "Project"
        filename = f"AI_Bug_Hunter_Report_{proj_name}_{scan_id}.json"
        return JSONResponse(
            content=data,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    elif report_format == "pdf":
        pdf_path = settings.REPORT_DIR / f"report_{scan_id}.pdf"
        # Regenerate report on-demand to include any updated AI explanations
        generate_pdf_report(scan, project, vulnerabilities, pdf_path)
        proj_name = project.name if project else "Project"
        return FileResponse(
            str(pdf_path),
            media_type="application/pdf",
            filename=f"AI_Bug_Hunter_Report_{proj_name}_{scan_id}.pdf"
        )

    elif report_format == "html":
        html_path = settings.REPORT_DIR / f"report_{scan_id}.html"
        generate_html_report(scan, project, vulnerabilities, html_path)
        proj_name = project.name if project else "Project"
        return FileResponse(
            str(html_path),
            media_type="text/html",
            filename=f"AI_Bug_Hunter_Report_{proj_name}_{scan_id}.html"
        )

    elif report_format == "csv":
        import io
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Finding ID", "Severity", "Category", "File Path", "Line Number",
            "Scanner Tool", "Message", "Remediation", "Status"
        ])
        for v in vulnerabilities:
            writer.writerow([
                f"VULN-{v.id}",
                v.severity,
                v.category,
                v.file_path,
                v.line_number or 1,
                v.tool_name,
                v.message,
                v.remediation or "",
                v.status or "open"
            ])
        proj_name = project.name if project else "Project"
        filename = f"AI_Bug_Hunter_Report_{proj_name}_{scan_id}.csv"
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )

    else:
        raise HTTPException(status_code=400, detail="Invalid report format. Must be json, pdf, html, or csv")


# --- DASHBOARD & STATISTICS ---

@router.get("/dashboard/summary", response_model=DashboardSummary)
def get_dashboard_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == "admin":
        projects = db.query(Project).all()
        scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    else:
        projects = db.query(Project).filter(Project.owner_id == current_user.id).all()
        project_ids = [p.id for p in projects]
        scans = db.query(Scan).filter(Scan.project_id.in_(project_ids)).order_by(Scan.created_at.desc()).all() if project_ids else []

    total_scans = len(scans)
    completed_scans = [s for s in scans if s.status == "completed"]
    
    critical_sum = sum((s.critical_count or 0) for s in completed_scans)
    high_sum = sum((s.high_count or 0) for s in completed_scans)
    medium_sum = sum((s.medium_count or 0) for s in completed_scans)
    low_sum = sum((s.low_count or 0) for s in completed_scans)
    total_vulnerabilities = sum((s.total_vulnerabilities or 0) for s in completed_scans)

    # Calculate resolved/fixed vulnerabilities
    scan_ids = [s.id for s in scans]
    fixed_count = 0
    if scan_ids:
        fixed_count = db.query(Vulnerability).filter(
            Vulnerability.scan_id.in_(scan_ids),
            Vulnerability.status == "resolved"
        ).count()

    penalty = critical_sum * 15 + high_sum * 8 + medium_sum * 3 + low_sum * 1
    security_score = max(0, min(100, 100 - penalty))

    recent_scans = scans[:10]

    return DashboardSummary(
        critical=critical_sum,
        high=high_sum,
        medium=medium_sum,
        low=low_sum,
        total_scans=total_scans,
        total_vulnerabilities=total_vulnerabilities,
        fixed_vulnerabilities=fixed_count,
        security_score=security_score,
        recent_scans=recent_scans
    )

@router.get("/dashboard/stats", response_model=ScanStats)
def get_dashboard_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == "admin":
        projects = db.query(Project).all()
        scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    else:
        projects = db.query(Project).filter(Project.owner_id == current_user.id).all()
        project_ids = [p.id for p in projects]
        scans = db.query(Scan).filter(Scan.project_id.in_(project_ids)).order_by(Scan.created_at.desc()).all() if project_ids else []

    total_scans = len(scans)
    completed_scans = [s for s in scans if s.status == "completed"]
    
    critical_sum = sum((s.critical_count or 0) for s in completed_scans)
    high_sum = sum((s.high_count or 0) for s in completed_scans)
    medium_sum = sum((s.medium_count or 0) for s in completed_scans)
    low_sum = sum((s.low_count or 0) for s in completed_scans)
    total_vulnerabilities = sum((s.total_vulnerabilities or 0) for s in completed_scans)

    severity = SeverityStats(
        critical=critical_sum,
        high=high_sum,
        medium=medium_sum,
        low=low_sum,
        info=0
    )

    recent_scans = scans[:10]

    return ScanStats(
        total_scans=total_scans,
        total_vulnerabilities=total_vulnerabilities,
        severity_distribution=severity,
        scans_history=recent_scans
    )

# --- SETTINGS & ADMIN ---

@router.get("/settings", response_model=AppSettings)
async def get_settings():
    try:
        models = await openrouter_client.list_models()
    except Exception:
        models = []

    return AppSettings(
        openrouter_api_url=settings.OPENROUTER_API_BASE_URL,
        ollama_url=settings.OPENROUTER_API_BASE_URL,
        default_model=settings.DEFAULT_LLM_MODEL,
        available_models=models,
        ai_provider=settings.AI_PROVIDER,
        openrouter_api_key_configured=bool(settings.OPENROUTER_API_KEY),
        openai_api_key_configured=bool(settings.OPENAI_API_KEY),
        gemini_api_key_configured=bool(settings.GEMINI_API_KEY),
        groq_api_key_configured=bool(settings.GROQ_API_KEY),
        claude_api_key_configured=bool(settings.CLAUDE_API_KEY),
        grok_api_key_configured=bool(settings.GROK_API_KEY)
    )

def save_settings_to_env(
    openrouter_api_url: Optional[str] = None,
    default_model: Optional[str] = None,
    ai_provider: str = "openrouter",
    openrouter_api_key: Optional[str] = None,
    openai_api_key: Optional[str] = None,
    gemini_api_key: Optional[str] = None,
    groq_api_key: Optional[str] = None,
    claude_api_key: Optional[str] = None,
    grok_api_key: Optional[str] = None,
    ollama_url: Optional[str] = None,
):
    # Update settings object in-memory
    if openrouter_api_url is not None:
        settings.OPENROUTER_API_BASE_URL = openrouter_api_url
        settings.OLLAMA_API_URL = openrouter_api_url
    elif ollama_url is not None:
        settings.OPENROUTER_API_BASE_URL = ollama_url
        settings.OLLAMA_API_URL = ollama_url

    if default_model is not None:
        settings.DEFAULT_LLM_MODEL = default_model
    if ai_provider is not None:
        settings.AI_PROVIDER = ai_provider
    
    if openrouter_api_key is not None:
        settings.OPENROUTER_API_KEY = openrouter_api_key
    if openai_api_key is not None:
        settings.OPENAI_API_KEY = openai_api_key
    if gemini_api_key is not None:
        settings.GEMINI_API_KEY = gemini_api_key
    if groq_api_key is not None:
        settings.GROQ_API_KEY = groq_api_key
    if claude_api_key is not None:
        settings.CLAUDE_API_KEY = claude_api_key
    if grok_api_key is not None:
        settings.GROK_API_KEY = grok_api_key
        
    openrouter_client.base_url = settings.OPENROUTER_API_BASE_URL
    
    # Save back to .env preserving other existing configs
    env_path = settings.BASE_DIR / ".env"
    env_vars = {}
    if env_path.exists():
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        parts = line.split("=", 1)
                        env_vars[parts[0].strip()] = parts[1].strip()
        except Exception:
            pass
            
    # Update settings
    env_vars["OPENROUTER_API_BASE_URL"] = settings.OPENROUTER_API_BASE_URL
    env_vars["DEFAULT_LLM_MODEL"] = settings.DEFAULT_LLM_MODEL
    env_vars["AI_PROVIDER"] = settings.AI_PROVIDER
    
    if settings.OPENROUTER_API_KEY:
        env_vars["OPENROUTER_API_KEY"] = settings.OPENROUTER_API_KEY
    if settings.OPENAI_API_KEY:
        env_vars["OPENAI_API_KEY"] = settings.OPENAI_API_KEY
    if settings.GEMINI_API_KEY:
        env_vars["GEMINI_API_KEY"] = settings.GEMINI_API_KEY
    if settings.GROQ_API_KEY:
        env_vars["GROQ_API_KEY"] = settings.GROQ_API_KEY
    if settings.CLAUDE_API_KEY:
        env_vars["CLAUDE_API_KEY"] = settings.CLAUDE_API_KEY
    if settings.GROK_API_KEY:
        env_vars["GROK_API_KEY"] = settings.GROK_API_KEY
        
    try:
        with open(env_path, "w", encoding="utf-8") as f:
            for k, v in env_vars.items():
                f.write(f"{k}={v}\n")
    except Exception:
        pass

@router.post("/settings", response_model=AppSettings)
async def update_settings(
    settings_in: SettingsUpdate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    current_url = settings.OPENROUTER_API_BASE_URL
    current_model = settings.DEFAULT_LLM_MODEL
    current_provider = settings.AI_PROVIDER
    
    new_url = settings_in.openrouter_api_url or settings_in.ollama_url or current_url
    new_model = settings_in.default_model if settings_in.default_model is not None else current_model
    new_provider = settings_in.ai_provider if settings_in.ai_provider is not None else current_provider
    
    # Save settings
    save_settings_to_env(
        openrouter_api_url=new_url, 
        default_model=new_model, 
        ai_provider=new_provider,
        openrouter_api_key=settings_in.openrouter_api_key,
        openai_api_key=settings_in.openai_api_key,
        gemini_api_key=settings_in.gemini_api_key,
        groq_api_key=settings_in.groq_api_key,
        claude_api_key=settings_in.claude_api_key,
        grok_api_key=settings_in.grok_api_key
    )
    
    # List models with updated client
    try:
        models = await openrouter_client.list_models()
    except Exception:
        models = []
        
    return AppSettings(
        openrouter_api_url=settings.OPENROUTER_API_BASE_URL,
        ollama_url=settings.OPENROUTER_API_BASE_URL,
        default_model=settings.DEFAULT_LLM_MODEL,
        available_models=models,
        ai_provider=settings.AI_PROVIDER,
        openrouter_api_key_configured=bool(settings.OPENROUTER_API_KEY),
        openai_api_key_configured=bool(settings.OPENAI_API_KEY),
        gemini_api_key_configured=bool(settings.GEMINI_API_KEY),
        groq_api_key_configured=bool(settings.GROQ_API_KEY),
        claude_api_key_configured=bool(settings.CLAUDE_API_KEY),
        grok_api_key_configured=bool(settings.GROK_API_KEY)
    )

@router.get("/admin/users", response_model=List[UserResponse])
def admin_list_users(current_admin: User = Depends(get_current_admin), db: Session = Depends(get_db)):
    users = db.query(User).all()
    if not users and current_admin:
        return [current_admin]
    return users

@router.post("/admin/users/{user_id}/role")
def admin_update_role(
    user_id: int, 
    role: str, 
    current_admin: User = Depends(get_current_admin), 
    db: Session = Depends(get_db)
):
    if role not in ("admin", "developer"):
        raise HTTPException(status_code=400, detail="Invalid role type")
        
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    user.role = role
    db.commit()
    return {"message": f"User role updated to {role}"}

@router.post("/admin/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def admin_create_user(
    user_in: UserCreate,
    role: str = "developer",
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    if role not in ("admin", "developer"):
        raise HTTPException(status_code=400, detail="Invalid role type")
        
    existing_user = db.query(User).filter(User.username == user_in.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
        
    hashed_password = get_password_hash(user_in.password)
    new_user = User(
        username=user_in.username,
        hashed_password=hashed_password,
        role=role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.delete("/admin/users/{user_id}")
def admin_delete_user(
    user_id: int, 
    current_admin: User = Depends(get_current_admin), 
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account")
        
    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

