import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database import SessionLocal
from backend.models import Scan, Project

db = SessionLocal()
try:
    scans = db.query(Scan).filter(Scan.status.in_(["failed", "pending", "scanning"])).all()
    print(f"Found {len(scans)} pending/failed/scanning scan(s).")
    for s in scans:
        print(f"Scan ID {s.id} (Project {s.project_id}): Status was {s.status}")
        # Reset failed scans to pending or completed if finished
        if s.status == "failed":
            s.status = "pending"
            s.progress = 0
            db.commit()
            print(f"  -> Reset Scan ID {s.id} to pending.")
finally:
    db.close()
