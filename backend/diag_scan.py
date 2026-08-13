"""
Diagnostic script: runs the full scan engine with detailed exception tracing
to find what's causing scans to fail.
"""
import sys
import traceback
import os
from pathlib import Path

# Make sure backend package is importable
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

print(f"Python: {sys.version}")
print(f"CWD: {os.getcwd()}")
print(f"ROOT: {ROOT}")
print("-" * 60)

# ---- Step 1: Import checks ----
print("[1] Testing imports...")
try:
    from backend.config import settings
    print(f"    OK: settings loaded. AI_PROVIDER={settings.AI_PROVIDER}, LLM={settings.DEFAULT_LLM_MODEL}")
except Exception as e:
    print(f"    FAIL: config import: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    from backend.database import SessionLocal, Base
    print("    OK: database SessionLocal imported")
except Exception as e:
    print(f"    FAIL: database import: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    from backend.models import Project, Scan, Vulnerability
    print("    OK: models imported")
except Exception as e:
    print(f"    FAIL: models import: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    from backend.scanner.gitleaks_runner import GitleaksRunner
    from backend.scanner.bandit_runner import BanditRunner
    from backend.scanner.semgrep_runner import SemgrepRunner
    from backend.scanner.dependency_runner import DependencyRunner
    print("    OK: all scanner runners imported")
except Exception as e:
    print(f"    FAIL: scanner import: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    from backend.ai.ollama_client import ollama_client
    print("    OK: ollama_client imported")
except Exception as e:
    print(f"    FAIL: ollama_client import: {e}")
    traceback.print_exc()
    sys.exit(1)

# ---- Step 2: Test DB query ----
print("\n[2] Testing DB connection and project lookup...")
db = SessionLocal()
try:
    projects = db.query(Project).all()
    print(f"    OK: Found {len(projects)} project(s) in DB")
    if not projects:
        print("    WARNING: No projects found. Create a project first, then retry.")
        db.close()
        sys.exit(0)
    project = projects[0]
    print(f"    Using project: id={project.id}, name='{project.name}', path='{project.file_path}'")
except Exception as e:
    print(f"    FAIL: DB query failed: {e}")
    traceback.print_exc()
    db.close()
    sys.exit(1)

# ---- Step 3: Run each scanner in isolation ----
project_path_str = project.file_path
project_path = Path(project_path_str)

if not project_path.exists():
    print(f"\n    ERROR: Project path does not exist: {project_path_str}")
    print("    This is the root cause — the uploaded file directory is missing.")
    db.close()
    sys.exit(1)

print(f"\n[3] Running scanner modules against: {project_path_str}")

# Gitleaks
print("\n  [3a] GitleaksRunner.scan()...")
try:
    g = GitleaksRunner()
    res = g.scan(project_path_str)
    print(f"       OK: {len(res)} finding(s)")
except Exception as e:
    print(f"       FAIL: {e}")
    traceback.print_exc()

# Bandit
print("\n  [3b] BanditRunner.scan()...")
try:
    b = BanditRunner()
    res = b.scan(project_path_str)
    print(f"       OK: {len(res)} finding(s)")
except Exception as e:
    print(f"       FAIL: {e}")
    traceback.print_exc()

# Semgrep
print("\n  [3c] SemgrepRunner.scan()...")
try:
    s = SemgrepRunner()
    res = s.scan(project_path_str)
    print(f"       OK: {len(res)} finding(s)")
except Exception as e:
    print(f"       FAIL: {e}")
    traceback.print_exc()

# Dependency
print("\n  [3d] DependencyRunner.scan()...")
try:
    d = DependencyRunner()
    res = d.scan(project_path_str)
    print(f"       OK: {len(res)} finding(s)")
except Exception as e:
    print(f"       FAIL: {e}")
    traceback.print_exc()

# ---- Step 4: Full engine run ----
print("\n[4] Running full execute_scan_task()...")
from backend.scanner.engine import execute_scan_task

scan = Scan(project_id=project.id, status="pending", progress=0)
db.add(scan)
db.commit()
db.refresh(scan)
scan_id = scan.id
print(f"    Created diagnostic scan id={scan_id}")
db.close()

try:
    execute_scan_task(SessionLocal, scan_id, project_path_str)
    # Re-open DB to check result
    db2 = SessionLocal()
    result_scan = db2.query(Scan).filter(Scan.id == scan_id).first()
    print(f"\n    RESULT: status={result_scan.status}, progress={result_scan.progress}, vulns={result_scan.total_vulnerabilities}")
    db2.close()
except Exception as e:
    print(f"    FAIL: execute_scan_task raised: {e}")
    traceback.print_exc()

print("\n[DONE] Diagnostics complete.")
