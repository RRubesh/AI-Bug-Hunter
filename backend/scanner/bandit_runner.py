import ast
import os
import shutil
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any

class PythonASTScanner(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []
        self.current_lines = []

    def scan(self, code_text: str):
        try:
            self.current_lines = code_text.splitlines()
            tree = ast.parse(code_text, self.file_path)
            self.visit(tree)
        except SyntaxError as e:
            # Report syntax errors as a low priority alert
            self.findings.append({
                "file_path": self.file_path,
                "line_number": e.lineno or 1,
                "code_snippet": code_text.splitlines()[e.lineno - 1] if e.lineno and e.lineno <= len(code_text.splitlines()) else "",
                "severity": "LOW",
                "category": "Syntax Error",
                "message": f"Syntax error prevented full security analysis: {e.msg}",
                "tool_name": "Bandit (AST Fallback)",
                "remediation": "Fix syntax error to enable static analysis scanning."
            })
        except Exception as e:
            pass
        return self.findings

    def _add_finding(self, node: ast.AST, severity: str, category: str, message: str, remediation: str):
        line_num = getattr(node, "lineno", 1)
        snippet = ""
        if self.current_lines and 1 <= line_num <= len(self.current_lines):
            snippet = self.current_lines[line_num - 1].strip()
            
        self.findings.append({
            "file_path": self.file_path,
            "line_number": line_num,
            "code_snippet": snippet,
            "severity": severity,
            "category": category,
            "message": message,
            "tool_name": "Bandit (AST Fallback)",
            "remediation": remediation
        })

    def visit_Call(self, node: ast.Call):
        # 1. Check for eval and exec
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self._add_finding(
                node,
                severity="HIGH",
                category="Code Injection",
                message=f"Use of '{node.func.id}()' detected. Executing arbitrary code can lead to remote code execution (RCE).",
                remediation="Refactor the code to avoid executing dynamic strings. Use structured formats like JSON or safe dict lookups instead."
            )

        # 2. Check for os.system or subprocess calls
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            # os.system(...)
            if node.func.value.id == "os" and node.func.attr == "system":
                self._add_finding(
                    node,
                    severity="HIGH",
                    category="Command Injection",
                    message="Use of 'os.system()' can lead to Command Injection if input contains shell metacharacters.",
                    remediation="Use the 'subprocess' module with 'shell=False' and pass arguments as a list to prevent command shell evaluation."
                )
            
            # subprocess calls
            elif node.func.value.id == "subprocess" and node.func.attr in ("Popen", "run", "call", "check_output"):
                # Check if shell=True is passed
                shell_true = False
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        shell_true = True
                
                if shell_true:
                    self._add_finding(
                        node,
                        severity="HIGH",
                        category="Command Injection",
                        message=f"Calling 'subprocess.{node.func.attr}()' with shell=True is highly vulnerable to shell injections.",
                        remediation="Set shell=False and pass arguments as a list of strings instead."
                    )

        # 3. Check for weak hashing (MD5 / SHA1)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib" and node.func.attr in ("md5", "sha1"):
                self._add_finding(
                    node,
                    severity="MEDIUM",
                    category="Weak Cryptography",
                    message=f"Use of weak hash function 'hashlib.{node.func.attr}()' detected. These algorithms are cryptographically broken.",
                    remediation="Use secure hashes like SHA-256, SHA-512, or password hashing libraries like bcrypt/argon2."
                )

        # 4. Check for tempfile.mktemp
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "tempfile" and node.func.attr == "mktemp":
                self._add_finding(
                    node,
                    severity="MEDIUM",
                    category="Insecure Temp File",
                    message="Use of 'tempfile.mktemp()' is deprecated and vulnerable to race conditions.",
                    remediation="Use 'tempfile.mkstemp()' or 'tempfile.TemporaryFile()' instead."
                )

        # 5. SQL Injection via string interpolation in cursor executions
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            # Check if executing query
            if len(node.args) > 0:
                first_arg = node.args[0]
                is_dangerous = False
                
                # Check if formatted string (f-string)
                if isinstance(first_arg, ast.JoinedStr):
                    # Check if query looks like SQL
                    is_dangerous = True
                # Check if string concatenation (%)
                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Mod, ast.Add)):
                    # string % values or string + values
                    is_dangerous = True
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                    # "sql".format(...)
                    is_dangerous = True
                
                if is_dangerous:
                    self._add_finding(
                        node,
                        severity="HIGH",
                        category="SQL Injection",
                        message="Potential SQL Injection. Query built using string formatting or interpolation rather than parameterized queries.",
                        remediation="Always use parameterized queries (e.g. `cursor.execute('SELECT * FROM users WHERE name = %s', (name,))`) to pass user inputs."
                    )

        # Continue traversal
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Check for potential SQL injection variable formatting
        if isinstance(node.value, (ast.BinOp, ast.JoinedStr, ast.Call)):
            is_sql_pattern = False
            line_num = getattr(node, "lineno", 1)
            if self.current_lines and 1 <= line_num <= len(self.current_lines):
                line_content = self.current_lines[line_num - 1].upper()
                if any(x in line_content for x in ("SELECT", "INSERT", "UPDATE", "DELETE")) and \
                   any(y in line_content for y in ("+", "%", ".FORMAT", "F\"", "F'")):
                    is_sql_pattern = True
            
            if is_sql_pattern:
                self._add_finding(
                    node,
                    severity="HIGH",
                    category="SQL Injection",
                    message="Variable assignment contains dynamic SQL query building. String formatting or addition should be replaced by parameterized SQL placeholders.",
                    remediation="Use parameterized queries instead of concatenating variables directly in the query assignment."
                )
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        self._add_finding(
            node,
            severity="LOW",
            category="Insecure Assert",
            message="Use of 'assert' detected. Assert statements are compiled away in production mode (python -O), skipping their verification check.",
            remediation="Replace assertions with explicit conditional checks and raise appropriate exceptions (e.g. ValueError)."
        )
        self.generic_visit(node)


class BanditRunner:
    def __init__(self, use_cli: bool = True):
        self.use_cli = use_cli
        self.bandit_path = shutil.which("bandit")

    def scan(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        target_path = Path(target_dir)

        # 1. Try Bandit CLI if installed
        if self.use_cli and self.bandit_path:
            try:
                report_file = target_path / "bandit_report.json"
                cmd = [
                    self.bandit_path,
                    "-f", "json",
                    "-o", str(report_file),
                    "-r", str(target_path),
                    "--quiet"
                ]
                subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if report_file.exists():
                    with open(report_file, "r") as f:
                        data = json.load(f)
                    
                    results = data.get("results", [])
                    for item in results:
                        if not isinstance(item, dict):
                            continue
                        filename_val = item.get("filename") or ""
                        rel_path = os.path.relpath(filename_val, target_dir).replace('\\', '/') if (filename_val and os.path.isabs(filename_val)) else (filename_val or "main.py")
                        
                        findings.append({
                            "file_path": rel_path,
                            "line_number": item.get("line_number") or 1,
                            "code_snippet": str(item.get("code") or "").strip(),
                            "severity": str(item.get("issue_severity") or "MEDIUM").upper(),
                            "category": str(item.get("issue_text") or "Python Security Issue"),
                            "message": f"{item.get('test_id', 'B000')}: {item.get('issue_text', 'Issue detected')}",
                            "tool_name": "Bandit",
                            "remediation": "Apply secure coding principles: avoid shell execution, parameterized inputs, and use secure crypto algorithms."
                        })
                    os.remove(report_file)
                    return findings
            except Exception as e:
                print(f"Bandit CLI error: {str(e)}. Falling back to AST scanner.")

        # 2. Native AST static analyzer fallback
        walk_items = []
        if target_path.is_file():
            walk_items = [(str(target_path.parent), [], [target_path.name])]
        elif target_path.is_dir():
            walk_items = os.walk(target_path)
        else:
            return findings

        for root, _, files in walk_items:
            for file in files:
                if file.endswith('.py'):
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
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            code_text = f.read()
                        
                        scanner = PythonASTScanner(relative_path)
                        file_findings = scanner.scan(code_text)
                        findings.extend(file_findings)
                    except Exception:
                        continue
                        
        return findings
