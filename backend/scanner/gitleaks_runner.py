import re
import os
import shutil
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any

# Define highly optimized patterns for typical API secrets
SECRET_PATTERNS = [
    {
        "category": "SSH Private Key",
        "pattern": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
        "severity": "CRITICAL",
        "message": "SSH or SSL private key has been exposed in source code."
    },
    {
        "category": "AWS Client ID",
        "pattern": r"\b(AKIA|ASCA|ASIA)[0-9A-Z]{16}\b",
        "severity": "HIGH",
        "message": "AWS Access Key ID exposed in cleartext."
    },
    {
        "category": "AWS Secret Access Key",
        "pattern": r"(?i)(?:aws_secret_access_key|aws_secret|aws_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "severity": "CRITICAL",
        "message": "AWS Secret Access Key exposed in cleartext. Revoke immediately."
    },
    {
        "category": "Slack OAuth Token",
        "pattern": r"xox[bapts]-[0-9a-zA-Z]{10,48}",
        "severity": "CRITICAL",
        "message": "Slack Access Token detected, exposing workspace channels."
    },
    {
        "category": "Stripe API Key",
        "pattern": r"\brk_(live|test)_[0-9a-zA-Z]{24}\b|\bsk_(live|test)_[0-9a-zA-Z]{24}\b",
        "severity": "CRITICAL",
        "message": "Stripe API key (Secret or Restricted) found in source code."
    },
    {
        "category": "GitHub Token",
        "pattern": r"\b(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}\b",
        "severity": "HIGH",
        "message": "GitHub Personal Access Token or OAuth Token exposed."
    },
    {
        "category": "OpenAI API Key",
        "pattern": r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{32,}\b",
        "severity": "CRITICAL",
        "message": "OpenAI API key exposed in cleartext."
    },
    {
        "category": "Google API Key",
        "pattern": r"\bAIza[0-9A-Za-z-_]{35}\b",
        "severity": "HIGH",
        "message": "Google Cloud API Key exposed in source code."
    },
    {
        "category": "Database URL Credential",
        "pattern": r"\b[a-zA-Z]{3,10}://[^:\s]+:[^@\s]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_-]+\b",
        "severity": "CRITICAL",
        "message": "Database connection string containing explicit username and password."
    },
    {
        "category": "Generic Password/Token",
        "pattern": r"(?i)\b(?:db_password|database_pwd|api_secret|jwt_secret|client_secret|client_private_key|secret_key|api_key|app_secret)\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]",
        "severity": "HIGH",
        "message": "Potential hardcoded credential or API password."
    }
]

class GitleaksRunner:
    def __init__(self, use_cli: bool = True):
        self.use_cli = use_cli
        self.gitleaks_path = shutil.which("gitleaks")

    def scan(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        target_path = Path(target_dir)

        # 1. Attempt Gitleaks CLI if available and requested
        if self.use_cli and self.gitleaks_path:
            try:
                report_file = target_path / "gitleaks_report.json"
                # Run gitleaks directory scan
                cmd = [
                    self.gitleaks_path,
                    "detect",
                    "--source", str(target_path),
                    "--report-format", "json",
                    "--report-path", str(report_file),
                    "--no-git",
                    "--exit-code", "0"
                ]
                subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if report_file.exists():
                    with open(report_file, "r") as f:
                        cli_findings = json.load(f)
                    
                    # Convert to uniform schema
                    for item in cli_findings:
                        if not isinstance(item, dict):
                            continue
                        findings.append({
                            "file_path": str(item.get("File") or "main.py"),
                            "line_number": item.get("StartLine") or 1,
                            "code_snippet": str(item.get("Match") or ""),
                            "severity": "CRITICAL",  # secrets are almost always critical/high
                            "category": "Hardcoded Secret",
                            "message": f"Detected potential secret: {item.get('Description', 'Credential')}",
                            "tool_name": "Gitleaks",
                            "remediation": "Remove the secret immediately from source control, rotate the credential, and use an environment variable or secret manager."
                        })
                    
                    # Cleanup
                    os.remove(report_file)
                    return findings
            except Exception as e:
                # Log error and fallback to regex scan
                print(f"Gitleaks CLI error: {str(e)}. Falling back to regex scanner.")

        # 2. Native Regex Scanner (Highly robust fallback)
        walk_items = []
        if target_path.is_file():
            walk_items = [(str(target_path.parent), [], [target_path.name])]
        elif target_path.is_dir():
            walk_items = os.walk(target_path)
        else:
            return findings

        for root, _, files in walk_items:
            for file in files:
                # Skip non-text files or dotfiles or large files
                if file.startswith('.') or file.endswith(('.png', '.jpg', '.jpeg', '.zip', '.pdf', '.exe', '.db', '.pyc', '.gif', '.svg')):
                    continue
                
                full_path = Path(root) / file
                try:
                    if target_path.is_file():
                        relative_path = target_path.name
                    else:
                        relative_path = full_path.relative_to(target_path).as_posix()
                except Exception:
                    try:
                        relative_path = os.path.relpath(str(full_path), str(target_path)).replace('\\', '/')
                    except Exception:
                        relative_path = file

                try:
                    # Skip files > 5MB to avoid hang
                    if full_path.stat().st_size > 5 * 1024 * 1024:
                        continue
                        
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        
                    for line_num, line in enumerate(lines, 1):
                        for pattern_info in SECRET_PATTERNS:
                            matches = re.findall(pattern_info["pattern"], line)
                            if matches:
                                findings.append({
                                    "file_path": relative_path,
                                    "line_number": line_num,
                                    "code_snippet": line.strip(),
                                    "severity": pattern_info["severity"],
                                    "category": "Hardcoded Secret",
                                    "message": f"{pattern_info['category']}: {pattern_info['message']}",
                                    "tool_name": "Gitleaks (Fallback Engine)",
                                    "remediation": "Remove the hardcoded secret. Reference it using Environment Variables (e.g. `os.environ` or `.env` files) or store it in a secure Vault / Secrets Manager."
                                })
                except Exception:
                    # Skip unreadable files
                    continue

        return findings
