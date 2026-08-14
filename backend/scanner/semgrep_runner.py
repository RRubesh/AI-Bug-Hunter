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
    ],
    # Python
    ".py": [
        {
            "category": "Code Injection",
            "pattern": r"\b(eval|exec)\s*\(",
            "severity": "HIGH",
            "message": "Use of eval() or exec() can lead to arbitrary code execution (RCE).",
            "remediation": "Avoid evaluating dynamic string expressions. Use structured data formats like JSON."
        },
        {
            "category": "Command Injection",
            "pattern": r"os\.system\s*\(|subprocess\.(?:Popen|run|call|check_output)\s*\([^,)]*shell\s*=\s*True",
            "severity": "HIGH",
            "message": "Executing shell commands with shell=True or os.system() is vulnerable to command injection.",
            "remediation": "Pass arguments as a list of strings with shell=False."
        },
        {
            "category": "SQL Injection",
            "pattern": r"(?i)\.execute\s*\(\s*f['\"]|\.execute\s*\(\s*['\"].*(?:SELECT|INSERT|UPDATE|DELETE).*%|\.execute\s*\(\s*['\"].*\.format\(",
            "severity": "HIGH",
            "message": "Potential SQL Injection via dynamic string formatting in database query.",
            "remediation": "Use parameterized queries (e.g., `cursor.execute('SELECT * FROM t WHERE id=%s', (id,))`)."
        },
        {
            "category": "Insecure Deserialization",
            "pattern": r"pickle\.loads\s*\(|yaml\.load\s*\([^,)]*(?:Loader\s*=\s*yaml\.(?:UnsafeLoader|Loader))?",
            "severity": "HIGH",
            "message": "Untrusted deserialization via pickle or unsafe YAML loader can execute arbitrary Python objects.",
            "remediation": "Use yaml.safe_load() or JSON format for untrusted inputs."
        }
    ]
}

# Add TypeScript extensions (.ts, .tsx) sharing JS rules
LANGUAGE_RULES[".ts"] = LANGUAGE_RULES[".js"]
LANGUAGE_RULES[".tsx"] = LANGUAGE_RULES[".js"]
LANGUAGE_RULES[".jsx"] = LANGUAGE_RULES[".js"]

class SemgrepRunner:
    def __init__(self, use_cli: bool = True):
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
                subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if report_file.exists():
                    with open(report_file, "r") as f:
                        data = json.load(f)
                    
                    results = data.get("results", [])
                    for item in results:
                        if not isinstance(item, dict):
                            continue
                        path_in_item = item.get("path", "")
                        rel_path = os.path.relpath(path_in_item, target_dir).replace('\\', '/') if (path_in_item and os.path.isabs(path_in_item)) else (path_in_item or "main.py")
                        
                        extra = item.get("extra") or {}
                        metadata = extra.get("metadata") or {}
                        start_info = item.get("start") or {}
                        
                        findings.append({
                            "file_path": rel_path,
                            "line_number": start_info.get("line", 1) if isinstance(start_info, dict) else 1,
                            "code_snippet": str(extra.get("lines") or "").strip(),
                            "severity": str(extra.get("severity") or "MEDIUM").upper(),
                            "category": str(metadata.get("category") or "Security Vulnerability"),
                            "message": str(extra.get("message") or "Semgrep security finding"),
                            "tool_name": "Semgrep",
                            "remediation": str(extra.get("remediation") or "Apply standard secure coding practices to fix this issue.")
                        })
                    os.remove(report_file)
                    return findings
            except Exception as e:
                print(f"Semgrep CLI error: {str(e)}. Falling back to regex scanner.")

        # 2. Native Multi-Language Rule Fallback Scanner
        import re
        
        walk_items = []
        if target_path.is_file():
            walk_items = [(str(target_path.parent), [], [target_path.name])]
        elif target_path.is_dir():
            walk_items = os.walk(target_path)
        else:
            return findings

        for root, _, files in walk_items:
            for file in files:
                ext = Path(file).suffix.lower()
                if ext in LANGUAGE_RULES:
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
