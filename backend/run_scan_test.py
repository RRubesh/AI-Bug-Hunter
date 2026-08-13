import sys
import traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database import SessionLocal
from backend.models import Project, Scan, Vulnerability
from backend.scanner.engine import execute_scan_task

db = SessionLocal()
try:
    project = db.query(Project).filter(Project.id == 1).first()
    print(f"Testing Scan for Project ID={project.id}, Name={project.name}, Path={project.file_path}")
    
    scan = Scan(
        project_id=project.id,
        status="pending",
        progress=0
    )
    db.add(scan)
    db.commit()
    scan_id = scan.id
    
    print(f"Triggering execute_scan_task for scan {scan_id}...")
    execute_scan_task(SessionLocal, scan_id, project.file_path)
    
    db.refresh(scan)
    print(f"Scan Finished. Status: {scan.status}, Progress: {scan.progress}, Vulns: {scan.total_vulnerabilities}")
    
    # Check if there was any exception logged
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    print(f"Found {len(vulns)} vulnerabilities.")
    
except Exception as e:
    print("Scan test runner failed with exception:")
    traceback.print_exc()
finally:
    db.close()
