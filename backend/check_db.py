import sys
sys.path.append(r"c:\Deskop\AI Bug Hunter")

from backend.database import SessionLocal
from backend.models import Project, Scan, Vulnerability, User

db = SessionLocal()
try:
    print("--- USERS ---")
    users = db.query(User).all()
    for u in users:
        print(f"User: ID={u.id}, Username={u.username}, Role={u.role}")
        
    print("\n--- PROJECTS ---")
    projects = db.query(Project).all()
    for p in projects:
        print(f"Project: ID={p.id}, Name={p.name}, Lang={p.language_detected}, Upload={p.upload_type}")
        
    print("\n--- SCANS ---")
    scans = db.query(Scan).all()
    for s in scans:
        print(f"Scan: ID={s.id}, ProjectID={s.project_id}, Status={s.status}, Progress={s.progress}, Vulns={s.total_vulnerabilities}")
        
    print("\n--- VULNERABILITIES ---")
    vulns = db.query(Vulnerability).all()
    for v in vulns:
        print(f"Vuln: ID={v.id}, ScanID={v.scan_id}, Severity={v.severity}, Category={v.category}, Path={v.file_path}")
        
finally:
    db.close()
