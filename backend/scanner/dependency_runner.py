import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any

# Simple built-in vulnerable dependencies database
VULNERABLE_PACKAGES = {
    # JavaScript dependencies
    "npm": {
        "lodash": {
            "max_version": "4.17.20",
            "severity": "HIGH",
            "category": "Prototype Pollution",
            "message": "Lodash versions < 4.17.21 are vulnerable to Prototype Pollution which can lead to Remote Code Execution (RCE).",
            "remediation": "Upgrade lodash to 4.17.21 or higher."
        },
        "axios": {
            "max_version": "0.21.0",
            "severity": "MEDIUM",
            "category": "Server-Side Request Forgery (SSRF)",
            "message": "Axios versions < 0.21.1 contain an SSRF vulnerability when parsing absolute URLs.",
            "remediation": "Upgrade axios to 0.21.1 or higher."
        },
        "express": {
            "max_version": "4.16.0",
            "severity": "MEDIUM",
            "category": "Denial of Service (DoS)",
            "message": "Express versions < 4.16.1 contain vulnerabilities in qs module or body-parser.",
            "remediation": "Upgrade express to 4.16.1 or higher."
        },
        "minimist": {
            "max_version": "1.2.5",
            "severity": "HIGH",
            "category": "Prototype Pollution",
            "message": "Minimist versions < 1.2.6 are vulnerable to Prototype Pollution.",
            "remediation": "Upgrade minimist to 1.2.6 or higher."
        }
    },
    # Python dependencies
    "pip": {
        "requests": {
            "max_version": "2.20.0",
            "severity": "MEDIUM",
            "category": "Information Leak",
            "message": "Requests versions < 2.20.0 can leak credentials across redirects.",
            "remediation": "Upgrade requests to 2.20.0 or higher."
        },
        "django": {
            "max_version": "3.2.18",
            "severity": "CRITICAL",
            "category": "SQL Injection & XSS",
            "message": "Django versions < 3.2.19, < 4.0.10, or < 4.1.9 are subject to multiple security issues.",
            "remediation": "Upgrade django to 3.2.19, 4.1.9, or higher."
        },
        "urllib3": {
            "max_version": "1.26.4",
            "severity": "HIGH",
            "category": "ReDoS & CRLF Injection",
            "message": "Urllib3 versions < 1.26.5 are vulnerable to regular expression denial of service and CRLF injections.",
            "remediation": "Upgrade urllib3 to 1.26.5 or higher."
        },
        "jinja2": {
            "max_version": "2.11.2",
            "severity": "HIGH",
            "category": "Server-Side Template Injection (SSTI)",
            "message": "Jinja2 versions < 2.11.3 are vulnerable to Server-Side Template Injection (SSTI).",
            "remediation": "Upgrade jinja2 to 2.11.3 or higher."
        }
    }
}

class DependencyRunner:
    def __init__(self):
        pass

    def scan(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        target_path = Path(target_dir)

        # 1. Look for package.json
        package_json_path = target_path / "package.json"
        if package_json_path.exists():
            try:
                with open(package_json_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                
                dependencies = data.get("dependencies", {})
                dev_dependencies = data.get("devDependencies", {})
                all_deps = {**dependencies, **dev_dependencies}
                
                for pkg_name, pkg_ver_raw in all_deps.items():
                    # Strip characters like ^, ~, >=, <=, *
                    pkg_ver = re.sub(r"[^\d.]", "", pkg_ver_raw)
                    
                    if pkg_name in VULNERABLE_PACKAGES["npm"]:
                        vuln_info = VULNERABLE_PACKAGES["npm"][pkg_name]
                        if self._is_vulnerable(pkg_ver, vuln_info["max_version"]):
                            findings.append({
                                "file_path": "package.json",
                                "line_number": 1,
                                "code_snippet": f'"{pkg_name}": "{pkg_ver_raw}"',
                                "severity": vuln_info["severity"],
                                "category": "Vulnerable Dependency",
                                "message": vuln_info["message"],
                                "tool_name": "Dependency Analyzer",
                                "remediation": vuln_info["remediation"]
                            })
            except Exception as e:
                print(f"Error parsing package.json: {str(e)}")

        # 2. Look for requirements.txt
        req_txt_path = target_path / "requirements.txt"
        if req_txt_path.exists():
            try:
                with open(req_txt_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                
                for line_num, line in enumerate(lines, 1):
                    # Typical structure: package==1.2.3 or package>=1.2.3 or package
                    cleaned_line = line.strip().split('#')[0] # remove comments
                    if not cleaned_line:
                        continue
                    
                    # Split on operators
                    parts = re.split(r"==|>=|<=|>|<|~=", cleaned_line)
                    if parts:
                        pkg_name = str(parts[0]).strip().lower()
                        pkg_ver = str(parts[1]).strip() if len(parts) > 1 else ""
                        pkg_ver = re.sub(r"[^\d.]", "", pkg_ver)
                        
                        if pkg_name in VULNERABLE_PACKAGES["pip"]:
                            vuln_info = VULNERABLE_PACKAGES["pip"][pkg_name]
                            if not pkg_ver or self._is_vulnerable(pkg_ver, vuln_info["max_version"]):
                                findings.append({
                                    "file_path": "requirements.txt",
                                    "line_number": line_num,
                                    "code_snippet": line.strip(),
                                    "severity": str(vuln_info.get("severity") or "HIGH"),
                                    "category": "Vulnerable Dependency",
                                    "message": str(vuln_info.get("message") or "") + (f" (Detected version: {pkg_ver or 'unknown'})" if pkg_ver else ""),
                                    "tool_name": "Dependency Analyzer",
                                    "remediation": str(vuln_info.get("remediation") or "")
                                })
            except Exception as e:
                print(f"Error parsing requirements.txt: {str(e)}")

        return findings

    def _is_vulnerable(self, current_ver: str, max_vuln_ver: str) -> bool:
        if not current_ver:
            return True  # assume vulnerable if unspecified version
        
        try:
            curr_parts = [int(p) for p in current_ver.split('.') if p.isdigit()]
            max_parts = [int(p) for p in max_vuln_ver.split('.') if p.isdigit()]
            
            # Align lists length
            length = max(len(curr_parts), len(max_parts))
            curr_parts += [0] * (length - len(curr_parts))
            max_parts += [0] * (length - len(max_parts))
            
            for c, m in zip(curr_parts, max_parts):
                if c < m:
                    return True
                elif c > m:
                    return False
            return True  # equal is vulnerable since max is inclusive of vulnerability
        except Exception:
            return True
        return False
