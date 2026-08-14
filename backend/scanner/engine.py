import os
import time
import datetime
import zipfile
import threading
from pathlib import Path
from sqlalchemy.orm import Session
from backend.config import settings
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

def safe_commit(session: Session) -> bool:
    try:
        session.commit()
        return True
    except Exception as e:
        try:
            session.rollback()
        except Exception:
            pass
        print(f"[Scan Engine DB Notice]: {str(e)}")
        return False

def execute_scan_task(db_session_factory, scan_id: int, project_path_str: str):
    db: Session = db_session_factory()
    start_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        
        scan.status = "scanning"
        scan.progress = 10
        safe_commit(db)

        from backend.database import is_mongo_connected, get_mongo_db
        from backend.database.mongodb import mongo_manager

        project = db.query(Project).filter(Project.id == scan.project_id).first()
        user_id = project.owner_id if project else None

        mongo_manager.log_security_event(
            event_type="scan_started",
            description=f"Scan #{scan.id} started for project: {project.name if project else 'Unknown'}",
            user_id=user_id
        )

        project_path = Path(project_path_str) if project_path_str else Path(".")
        if not project_path.exists():
            folder_name = Path(project_path_str).name if project_path_str else ""
            candidate = settings.UPLOAD_DIR / folder_name if folder_name else None
            if candidate and candidate.exists():
                project_path = candidate
                if project:
                    project.file_path = str(project_path)
                    safe_commit(db)
            elif project and project.id:
                candidate_by_id = settings.UPLOAD_DIR / str(project.id)
                if candidate_by_id.exists():
                    project_path = candidate_by_id
                    project.file_path = str(project_path)
                    safe_commit(db)
            else:
                # If path still not found, fallback to UPLOAD_DIR root rather than crashing
                project_path = settings.UPLOAD_DIR

        # 1. Detect language
        language = detect_language(project_path if project_path.is_dir() else project_path.parent)
        if project:
            project.language_detected = language
            safe_commit(db)

        # Count total files
        total_files = 0
        scan_dir = project_path if project_path.is_dir() else project_path.parent
        if scan_dir.exists():
            for _, _, files in os.walk(scan_dir):
                total_files += len(files)
        if total_files == 0:
            total_files = 1

        # Initialize runners (with CLI auto-detection & fallback enabled)
        gitleaks = GitleaksRunner(use_cli=True)
        bandit = BanditRunner(use_cli=True)
        semgrep = SemgrepRunner(use_cli=True)
        dependency = DependencyRunner()

        findings = []
        raw_outputs = {}

        target_dir_str = str(scan_dir)

        # 2. Run Secret detection (25% progress)
        scan.progress = 25
        safe_commit(db)
        t0 = time.time()
        try:
            gitleaks_res = gitleaks.scan(target_dir_str) or []
            findings.extend(gitleaks_res)
            raw_outputs["gitleaks"] = {"execution_time": round(time.time() - t0, 3), "count": len(gitleaks_res), "findings": gitleaks_res}
        except Exception as e:
            print(f"Secret scanner error: {str(e)}")
            raw_outputs["gitleaks"] = {"execution_time": round(time.time() - t0, 3), "error": str(e)}

        # 3. Run Language-specific scans (50% progress)
        scan.progress = 50
        safe_commit(db)
        
        # Run Bandit AST analysis on Python files
        t0 = time.time()
        try:
            bandit_res = bandit.scan(target_dir_str) or []
            findings.extend(bandit_res)
            raw_outputs["bandit"] = {"execution_time": round(time.time() - t0, 3), "count": len(bandit_res), "findings": bandit_res}
        except Exception as e:
            print(f"Bandit scanner error: {str(e)}")
            raw_outputs["bandit"] = {"execution_time": round(time.time() - t0, 3), "error": str(e)}
        
        # Run Semgrep for multi-language AST/SAST rules (70% progress)
        scan.progress = 70
        safe_commit(db)
        t0 = time.time()
        try:
            semgrep_res = semgrep.scan(target_dir_str) or []
            findings.extend(semgrep_res)
            raw_outputs["semgrep"] = {"execution_time": round(time.time() - t0, 3), "count": len(semgrep_res), "findings": semgrep_res}
        except Exception as e:
            print(f"Semgrep scanner error: {str(e)}")
            raw_outputs["semgrep"] = {"execution_time": round(time.time() - t0, 3), "error": str(e)}

        # 4. Run Dependency scans (85% progress)
        scan.progress = 85
        safe_commit(db)
        t0 = time.time()
        try:
            dep_res = dependency.scan(target_dir_str) or []
            findings.extend(dep_res)
            raw_outputs["dependency_check"] = {"execution_time": round(time.time() - t0, 3), "count": len(dep_res), "findings": dep_res}
        except Exception as e:
            print(f"Dependency scanner error: {str(e)}")
            raw_outputs["dependency_check"] = {"execution_time": round(time.time() - t0, 3), "error": str(e)}

        # 5. Save findings and count statistics (90% progress)
        scan.progress = 90
        safe_commit(db)


        critical = high = medium = low = info = 0
        dedup_set = set()

        for item in findings:
            if not isinstance(item, dict):
                continue
            file_path = str(item.get("file_path") or "main.py")
            category = str(item.get("category") or "Security Vulnerability")
            line_num = item.get("line_number")
            dup_key = (file_path, line_num, category)
            if dup_key in dedup_set:
                continue
            dedup_set.add(dup_key)

            severity = str(item.get("severity") or "INFO").upper()
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
                file_path=file_path,
                line_number=line_num if isinstance(line_num, int) else 1,
                code_snippet=str(item.get("code_snippet") or ""),
                severity=severity,
                category=category,
                message=str(item.get("message") or "Security issue detected."),
                tool_name=str(item.get("tool_name") or "Scanner Engine"),
                remediation=str(item.get("remediation") or "Resolve this security risk according to OWASP standards."),
                status="open"
            )
            db.add(vuln)

        # Calculate security score (Start at 100, -15 per Critical, -8 per High, -3 per Medium, -1 per Low)
        penalty = critical * 15 + high * 8 + medium * 3 + low * 1
        security_score = max(0, min(100, 100 - penalty))

        scan.total_vulnerabilities = len(dedup_set)
        scan.critical_count = critical
        scan.high_count = high
        scan.medium_count = medium
        scan.low_count = low
        scan.progress = 100
        scan.status = "completed"
        finished_time = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        scan.finished_at = finished_time
        safe_commit(db)


        # 6. Asynchronously trigger AI explanations for top 3 high/critical items
        top_findings = db.query(Vulnerability).filter(
            Vulnerability.scan_id == scan.id,
            Vulnerability.severity.in_(["CRITICAL", "HIGH"])
        ).limit(3).all()

        for vuln in top_findings:
            try:
                explanation_data = ollama_client.explain_vulnerability_sync(
                    vuln.category or "Security Vulnerability",
                    vuln.message or "",
                    vuln.code_snippet or ""
                )
                if explanation_data and isinstance(explanation_data, dict):
                    vuln.ai_explanation = explanation_data.get("explanation")
                    vuln.ai_fix = explanation_data.get("fix")
                    safe_commit(db)
            except Exception as ai_err:
                print(f"AI explanation generation notice: {str(ai_err)}")

        # 7. Write to MongoDB Atlas collections
        try:
            if is_mongo_connected():
                mongo_db = get_mongo_db()
                if mongo_db is not None:
                    duration = (finished_time - start_time).total_seconds()
                    
                    # Update scans collection
                    mongo_db.scans.update_one(
                        {"scan_id": scan.id},
                        {"$set": {
                            "scan_id": scan.id,
                            "project_id": scan.project_id,
                            "user_id": user_id,
                            "scan_type": scan.trigger_type,
                            "status": scan.status,
                            "started_at": start_time,
                            "completed_at": finished_time,
                            "duration_seconds": round(duration, 2),
                            "total_files": total_files,
                            "critical_count": scan.critical_count,
                            "high_count": scan.high_count,
                            "medium_count": scan.medium_count,
                            "low_count": scan.low_count,
                            "total_vulnerabilities": scan.total_vulnerabilities,
                            "security_score": security_score,
                            "error_message": None
                        }},
                        upsert=True
                    )

                    # Update vulnerabilities collection
                    all_vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
                    for v in all_vulns:
                        mongo_db.vulnerabilities.update_one(
                            {"vulnerability_id": v.id},
                            {"$set": {
                                "vulnerability_id": v.id,
                                "scan_id": scan.id,
                                "project_id": scan.project_id,
                                "user_id": user_id,
                                "scanner": v.tool_name,
                                "severity": v.severity.lower(),
                                "title": v.category,
                                "description": v.message,
                                "category": v.category,
                                "cwe": "CWE-Unknown",
                                "owasp": "OWASP Top 10",
                                "file_path": v.file_path,
                                "line_number": v.line_number,
                                "code_snippet": v.code_snippet,
                                "evidence": v.message,
                                "recommendation": v.remediation,
                                "ai_explanation": v.ai_explanation,
                                "ai_fix": v.ai_fix,
                                "status": v.status or "open",
                                "created_at": v.created_at or finished_time
                            }},
                            upsert=True
                        )

                    # Update scanner_results collection
                    for engine_name, res_info in raw_outputs.items():
                        mongo_db.scanner_results.update_one(
                            {"scan_id": scan.id, "scanner": engine_name},
                            {"$set": {
                                "scan_id": scan.id,
                                "scanner": engine_name,
                                "status": "completed" if "error" not in res_info else "failed",
                                "execution_time": res_info.get("execution_time", 0.0),
                                "findings_count": res_info.get("count", 0),
                                "raw_output": str(res_info),
                                "normalized_output": res_info.get("findings", []),
                                "created_at": finished_time
                            }},
                            upsert=True
                        )

                    # Save AI analysis to ai_analysis collection
                    for v in all_vulns:
                        if v.ai_explanation or v.ai_fix:
                            mongo_db.ai_analysis.update_one(
                                {"vulnerability_id": v.id},
                                {"$set": {
                                    "scan_id": scan.id,
                                    "vulnerability_id": v.id,
                                    "model": settings.DEFAULT_LLM_MODEL,
                                    "explanation": v.ai_explanation,
                                    "risk_summary": v.message,
                                    "attack_scenario": "Exploit risk identified via SAST inspection.",
                                    "secure_recommendation": v.remediation,
                                    "fixed_code": v.ai_fix,
                                    "confidence": "HIGH",
                                    "created_at": finished_time
                                }},
                                upsert=True
                            )

                    # Log scan completed event
                    mongo_manager.log_security_event(
                        event_type="scan_completed",
                        description=f"Scan #{scan.id} finished cleanly with {scan.total_vulnerabilities} findings. Score: {security_score}/100",
                        user_id=user_id
                    )

        except Exception as mongo_err:
            print(f"MongoDB Atlas scan sync notice: {str(mongo_err)}")

    except Exception as e:
        try:
            db.rollback()
            err_scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if err_scan:
                err_scan.status = "failed"
                db.commit()
            
            from backend.database.mongodb import mongo_manager
            mongo_manager.log_security_event(
                event_type="scan_failed",
                description=f"Scan #{scan_id} failed: {str(e)}"
            )
        except Exception:
            pass
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

