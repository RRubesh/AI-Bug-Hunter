import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import settings
from backend.database import SessionLocal
from backend.models import Project, Scan

db = SessionLocal()
try:
    projects = db.query(Project).all()
    print(f"Checking {len(projects)} project(s)...")
    fixed_count = 0
    for p in projects:
        old_path = p.file_path
        if old_path:
            p_path = Path(old_path)
            if not p_path.exists():
                folder_name = p_path.name
                candidate = settings.UPLOAD_DIR / folder_name
                if candidate.exists():
                    p.file_path = str(candidate)
                    fixed_count += 1
                    print(f"Fixed Project ID {p.id} ({p.name}): '{old_path}' -> '{p.file_path}'")
                else:
                    candidate_id = settings.UPLOAD_DIR / str(p.id)
                    if candidate_id.exists():
                        p.file_path = str(candidate_id)
                        fixed_count += 1
                        print(f"Fixed Project ID {p.id} ({p.name}): '{old_path}' -> '{p.file_path}'")
                    else:
                        print(f"WARNING: Project ID {p.id} ({p.name}) directory not found: '{old_path}'")
    db.commit()
    print(f"Done! Fixed {fixed_count} project path(s).")
finally:
    db.close()
