import os
import time
import datetime
import zipfile
import threading
from pathlib import Path
from sqlalchemy.orm import Session
from backend.models import Project, Scan, Vulnerability
from backend.scanner.gitleaks_runner import GitleaksRunner
from backend.scanner.bandit_runner import BanditRunner
from backend.scanner.semgrep_runner import SemgrepRunner
from backend.scanner.dependency_runner import DependencyRunner
from backend.ai.ollama_client import ollama_client

def detect_language(project_path: Path) -> str:
    ext_counts = {}
    extensions_map = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript (React)",
        ".jsx": "JavaScript (React)",
        ".java": "Java",
        ".c": "C",
        ".cpp": "C++",
        ".cs": "C#",
        ".php": "PHP",
        ".go": "Go",
        ".rs": "Rust"
    }

    for root, _, files in os.walk(project_path):
        for file in files:
            ext = Path(file).suffix.lower()
            if ext in extensions_map:
                lang = extensions_map[ext]
                ext_counts[lang] = ext_counts.get(lang, 0) + 1

    if not ext_counts:
        return "Unknown"
    
    return max(ext_counts, key=ext_counts.get)

def extract_project_files(project_path: Path, upload_path: str):
    if upload_path.endswith('.zip'):
        with zipfile.ZipFile(upload_path, 'r') as zip_ref:
            zip_ref.extractall(project_path)
    # If folder, it's already there

def execute_scan_task(db_session_factory, scan_id: int, project_path_str: str):
    db: Session = db_session_factory()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        
        scan.status = "running"
        scan.progress = 10
        db.commit()

        project_path = Path(project_path_str)
        
        # 1. Detect language
        language = detect_language(project_path)
        project = db.query(Project).filter(Project.id == scan.project_id).first()
        if project:
            project.language_detected = language
            db.commit()

        # Initialize runners
        gitleaks = GitleaksRunner()
        bandit = BanditRunner()
        semgrep = SemgrepRunner()
        dependency = DependencyRunner()

        findings = []

        # 2. Run Secret detection (30% progress)
        scan.progress = 25
        db.commit()
        try:
            findings.extend(gitleaks.scan(project_path_str))
        except Exception as e:
            print(f"Secret scanner error: {str(e)}")

        # 3. Run Language-specific scans (50% progress)
        scan.progress = 50
        db.commit()
        
        if language == "Python":
            try:
                findings.extend(bandit.scan(project_path_str))
            except Exception as e:
                print(f"Bandit scanner error: {str(e)}")
        
        # Run Semgrep for all matching rules (70% progress)
        scan.progress = 70
        db.commit()
        try:
            findings.extend(semgrep.scan(project_path_str))
        except Exception as e:
            print(f"Semgrep scanner error: {str(e)}")

        # 4. Run Dependency scans (85% progress)
        scan.progress = 85
        db.commit()
        try:
            findings.extend(dependency.scan(project_path_str))
        except Exception as e:
            print(f"Dependency scanner error: {str(e)}")

        # 5. Save findings and count statistics (95% progress)
        scan.progress = 90
        db.commit()

        critical = high = medium = low = info = 0
        dedup_set = set()

        for item in findings:
            # Deduplicate items using file_path, line_number, and category
            dup_key = (item["file_path"], item.get("line_number"), item["category"])
            if dup_key in dedup_set:
                continue
            dedup_set.add(dup_key)

            severity = item["severity"].upper()
            if severity == "CRITICAL":
                critical += 1
            elif severity == "HIGH":
                high += 1
            elif severity == "MEDIUM":
                medium += 1
            elif severity in ("LOW", "WARNING"):
                severity = "LOW"
                low += 1
            else:
                severity = "INFO"
                info += 1

            vuln = Vulnerability(
                scan_id=scan.id,
                file_path=item["file_path"],
                line_number=item.get("line_number"),
                code_snippet=item.get("code_snippet"),
                severity=severity,
                category=item["category"],
                message=item["message"],
                tool_name=item["tool_name"],
                remediation=item.get("remediation", "Resolve this security risk according to OWASP standards.")
            )
            db.add(vuln)

        scan.total_vulnerabilities = len(dedup_set)
        scan.critical_count = critical
        scan.high_count = high
        scan.medium_count = medium
        scan.low_count = low
        scan.progress = 100
        scan.status = "completed"
        scan.finished_at = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        db.commit()

        # 6. Asynchronously trigger AI explanations for top 3 high/critical items immediately
        # (Other findings will generate AI details on-demand)
        top_findings = db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan.id,
            Vulnerability.severity.in_(["CRITICAL", "HIGH"])
        ).limit(3).all()

        for vuln in top_findings:
            try:
                # Synchronous in worker thread is fine since we are in background already
                explanation_data = ollama_client.explain_vulnerability_sync(
                    vuln.category, vuln.message, vuln.code_snippet
                )
                vuln.ai_explanation = explanation_data.get("explanation")
                vuln.ai_fix = explanation_data.get("fix")
                db.commit()
            except Exception as e:
                print(f"AI enrichment failed for vuln {vuln.id}: {str(e)}")

    except Exception as e:
        db.rollback()
        scan.status = "failed"
        db.commit()
        print(f"Scan id {scan_id} failed: {str(e)}")
    finally:
        db.close()

def start_background_scan(db_session_factory, scan_id: int, project_path_str: str):
    thread = threading.Thread(
        target=execute_scan_task,
        args=(db_session_factory, scan_id, project_path_str),
        daemon=True
    )
    thread.start()
