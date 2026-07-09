import os
import shutil
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any

# Multi-language rules for fallback regex static analysis
LANGUAGE_RULES = {
    # JavaScript & TypeScript
    ".js": [
        {
            "category": "Cross-Site Scripting (XSS)",
            "pattern": r"(?i)\.innerHTML\s*=|\.outerHTML\s*=|\bdocument\.write\s*\(",
            "severity": "HIGH",
            "message": "Direct assignment to innerHTML or use of document.write can lead to DOM-based XSS if user input is uncontrolled.",
            "remediation": "Use document.createElement / textContent, or utilize libraries that escape inputs automatically."
        },
        {
            "category": "React Insecure Rendering",
            "pattern": r"dangerouslySetInnerHTML\s*=\s*",
            "severity": "HIGH",
            "message": "Use of dangerouslySetInnerHTML bypasses React's built-in XSS protection.",
            "remediation": "Sanitize HTML using a library like DOMPurify before rendering, or refactor to use standard components."
        },
        {
            "category": "Command Injection",
            "pattern": r"child_process\.(?:exec|spawn)\s*\([^,)]*[\+\$`]",
            "severity": "CRITICAL",
            "message": "Calling shell execution command with string concatenation/interpolation can lead to Remote Command Execution (RCE).",
            "remediation": "Do not pass user input directly into commands. Use execFile or pass parameters in an arguments list with spawn."
        },
        {
            "category": "SQL Injection",
            "pattern": r"(?i)\.query\s*\(\s*['\"`].*(?:SELECT|INSERT|UPDATE|DELETE).*[\+\$`]",
            "severity": "HIGH",
            "message": "Raw SQL query constructed using string manipulation in JavaScript.",
            "remediation": "Use database query parameterization (e.g. `db.query('SELECT * FROM users WHERE id = ?', [id])`) or an ORM."
        }
    ],
    # Java
    ".java": [
        {
            "category": "SQL Injection",
            "pattern": r"(?i)\.executeQuery\s*\(\s*.*(?:SELECT|INSERT|UPDATE|DELETE).*\+",
            "severity": "HIGH",
            "message": "SQL query built with string concatenation instead of PreparedStatement.",
            "remediation": "Use PreparedStatement placeholders (`?`) and set variables using call setters (`setInt`, `setString`)."
        },
        {
            "category": "Weak Cryptography",
            "pattern": r"Cipher\.getInstance\(\s*\"(?:DES|Blowfish|RC4)",
            "severity": "MEDIUM",
            "message": "Use of weak cryptographic algorithms (DES/Blowfish/RC4) that are vulnerable to decryption attacks.",
            "remediation": "Upgrade encryption algorithm to AES (e.g. `AES/GCM/NoPadding`)."
        },
        {
            "category": "Command Injection",
            "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\+",
            "severity": "CRITICAL",
            "message": "Executing OS commands with dynamic string concatenation in Java.",
            "remediation": "Use ProcessBuilder and pass arguments as a list of strings rather than a raw command line."
        }
    ],
    # C & C++
    ".c": [
        {
            "category": "Buffer Overflow",
            "pattern": r"\b(strcpy|strcat|gets|sprintf)\s*\(",
            "severity": "HIGH",
            "message": "Insecure string function found. These functions do not check boundary limits and can lead to stack buffer overflows.",
            "remediation": "Replace with safe alternatives: 'strncpy', 'strncat', 'fgets', or 'snprintf'."
        }
    ],
    ".cpp": [
        {
            "category": "Buffer Overflow",
            "pattern": r"\b(strcpy|strcat|gets|sprintf)\s*\(",
            "severity": "HIGH",
            "message": "Insecure string function found. These functions do not check boundary limits and can lead to stack buffer overflows.",
            "remediation": "Replace with safe alternatives: 'strncpy', 'strncat', 'fgets', or 'snprintf'."
        }
    ],
    # PHP
    ".php": [
        {
            "category": "Code Injection",
            "pattern": r"\b(eval|assert|passthru|shell_exec|system)\s*\(",
            "severity": "CRITICAL",
            "message": "Dangerous execution function found in PHP. Arbitrary command execution is possible.",
            "remediation": "Avoid dynamic code execution. Sanitize inputs and restrict commands using strict whitelisting."
        },
        {
            "category": "SQL Injection",
            "pattern": r"(?i)\$wpdb->query\(|mysql_query\(|mysqli_query\(.*(?:\$|\+)",
            "severity": "HIGH",
            "message": "Direct query execution with concatenated strings in PHP.",
            "remediation": "Use prepared statements with PDO (PHP Data Objects) or wpdb prepare functions."
        }
    ],
    # Go
    ".go": [
        {
            "category": "Command Injection",
            "pattern": r"exec\.Command\s*\([^,)]*\+",
            "severity": "HIGH",
            "message": "Command creation using string concatenation can lead to command arguments modification.",
            "remediation": "Avoid string building for the command name or argument parameters. Pass them as distinct elements in the slice."
        }
    ]
}

# Add TypeScript extensions (.ts, .tsx) sharing JS rules
LANGUAGE_RULES[".ts"] = LANGUAGE_RULES[".js"]
LANGUAGE_RULES[".tsx"] = LANGUAGE_RULES[".js"]
LANGUAGE_RULES[".jsx"] = LANGUAGE_RULES[".js"]

class SemgrepRunner:
    def __init__(self, use_cli: bool = False):
        self.use_cli = use_cli
        self.semgrep_path = shutil.which("semgrep")

    def scan(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        target_path = Path(target_dir)

        # 1. Try Semgrep CLI if installed
        if self.use_cli and self.semgrep_path:
            try:
                report_file = target_path / "semgrep_report.json"
                cmd = [
                    self.semgrep_path,
                    "--config", "auto",
                    "--json",
                    "-o", str(report_file),
                    str(target_path)
                ]
                subprocess.run(cmd, capture_output=True, text=True)
                
                if report_file.exists():
                    with open(report_file, "r") as f:
                        data = json.load(f)
                    
                    results = data.get("results", [])
                    for item in results:
                        path_in_item = item.get("path", "")
                        rel_path = os.path.relpath(path_in_item, target_dir).replace('\\', '/') if os.path.isabs(path_in_item) else path_in_item
                        
                        extra = item.get("extra", {})
                        metadata = extra.get("metadata", {})
                        
                        findings.append({
                            "file_path": rel_path,
                            "line_number": item.get("start", {}).get("line", 1),
                            "code_snippet": extra.get("lines", "").strip(),
                            "severity": extra.get("severity", "MEDIUM").upper(),
                            "category": metadata.get("category", "Security Vulnerability"),
                            "message": extra.get("message", "Semgrep security finding"),
                            "tool_name": "Semgrep",
                            "remediation": extra.get("remediation", "Apply standard secure coding practices to fix this issue.")
                        })
                    os.remove(report_file)
                    return findings
            except Exception as e:
                print(f"Semgrep CLI error: {str(e)}. Falling back to regex scanner.")

        # 2. Native Multi-Language Rule Fallback Scanner
        import re
        
        for root, _, files in os.walk(target_path):
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in LANGUAGE_RULES:
                    full_path = Path(root) / file
                    relative_path = full_path.relative_to(target_path).as_posix()
                    rules = LANGUAGE_RULES[ext]
                    
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                            
                        for line_num, line in enumerate(lines, 1):
                            for rule in rules:
                                if re.search(rule["pattern"], line):
                                    findings.append({
                                        "file_path": relative_path,
                                        "line_number": line_num,
                                        "code_snippet": line.strip(),
                                        "severity": rule["severity"],
                                        "category": rule["category"],
                                        "message": rule["message"],
                                        "tool_name": f"Semgrep Fallback ({ext[1:].upper()} Analyzer)",
                                        "remediation": rule["remediation"]
                                    })
                    except Exception:
                        continue
                        
        return findings
