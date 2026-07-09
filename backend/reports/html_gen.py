import datetime
import html
from pathlib import Path
from backend.models import Scan, Project, Vulnerability

def safe_escape(val) -> str:
    if val is None:
        return ""
    return html.escape(str(val))

def generate_html_report(scan: Scan, project: Project, vulnerabilities: list, output_path: Path):
    vuln_cards = ""
    
    # Sort vulnerabilities by severity: Critical -> High -> Medium -> Low
    severity_weight = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    vulnerabilities.sort(key=lambda v: severity_weight.get(v.severity, 4))
    
    for idx, vuln in enumerate(vulnerabilities, 1):
        sev_badge_color = {
            "CRITICAL": "bg-red-500/10 text-red-500 border border-red-500/20",
            "HIGH": "bg-orange-500/10 text-orange-500 border border-orange-500/20",
            "MEDIUM": "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20",
            "LOW": "bg-blue-500/10 text-blue-500 border border-blue-500/20",
            "INFO": "bg-slate-500/10 text-slate-400 border border-slate-500/20"
        }.get(vuln.severity, "bg-slate-500/10 text-slate-400")

        # Escape dynamic variables to prevent HTML/script injection and formatting breaks
        escaped_code_snippet = safe_escape(vuln.code_snippet)
        escaped_ai_explanation = safe_escape(vuln.ai_explanation)
        escaped_ai_fix = safe_escape(vuln.ai_fix)
        escaped_severity = safe_escape(vuln.severity)
        escaped_category = safe_escape(vuln.category)
        escaped_file_path = safe_escape(vuln.file_path)
        escaped_tool_name = safe_escape(vuln.tool_name)
        escaped_message = safe_escape(vuln.message)
        escaped_remediation = safe_escape(vuln.remediation)

        code_snippet_html = ""
        if vuln.code_snippet:
            code_snippet_html = f"""
            <div class="mt-3">
                <span class="text-xs font-semibold text-slate-400">Vulnerable Code Snippet:</span>
                <pre class="mt-1 p-3 bg-slate-900 border border-slate-700/50 rounded-md overflow-x-auto"><code class="text-xs text-slate-300 font-mono">{escaped_code_snippet}</code></pre>
            </div>
            """

        ai_analysis_html = ""
        if vuln.ai_explanation:
            ai_analysis_html = f"""
            <div class="mt-4 pt-4 border-t border-slate-800">
                <span class="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path></svg>
                    AI Security Assessment:
                </span>
                <div class="mt-1 text-sm text-slate-300 whitespace-pre-line leading-relaxed">{escaped_ai_explanation}</div>
                {f'<div class="mt-3"><span class="text-xs font-semibold text-emerald-400">AI Secure Implementation:</span><pre class="mt-1 p-3 bg-emerald-950/20 border border-emerald-900/30 rounded-md overflow-x-auto"><code class="text-xs text-emerald-300 font-mono">{escaped_ai_fix}</code></pre></div>' if vuln.ai_fix else ''}
            </div>
            """

        vuln_cards += f"""
        <div class="p-6 bg-slate-800/40 border border-slate-800 rounded-xl hover:border-slate-700/80 transition-all duration-200">
            <div class="flex flex-wrap items-start justify-between gap-4">
                <div>
                    <div class="flex items-center gap-3">
                        <span class="px-2.5 py-0.5 text-xs font-bold rounded-full {sev_badge_color}">{escaped_severity}</span>
                        <h3 class="text-lg font-bold text-slate-100">#{idx} {escaped_category}</h3>
                    </div>
                    <p class="mt-1.5 text-xs text-slate-400 font-mono">{escaped_file_path} {f': Line {vuln.line_number}' if vuln.line_number else ''}</p>
                </div>
                <div class="text-right">
                    <span class="text-xs text-slate-500 font-semibold bg-slate-900 px-2.5 py-1 rounded-md border border-slate-800">{escaped_tool_name}</span>
                </div>
            </div>
            <p class="mt-3 text-sm text-slate-300">{escaped_message}</p>
            {code_snippet_html}
            <div class="mt-3 bg-slate-900/40 border border-slate-800 p-3 rounded-lg">
                <span class="text-xs font-semibold text-slate-400">Remediation Guide:</span>
                <p class="mt-0.5 text-sm text-slate-300">{escaped_remediation}</p>
            </div>
            {ai_analysis_html}
        </div>
        """

    escaped_project_name = safe_escape(project.name)
    escaped_project_description = safe_escape(project.description or 'Static security scan and code analysis summary.')
    escaped_project_language = safe_escape(project.language_detected or 'Unknown')
    escaped_project_upload_type = safe_escape(project.upload_type.upper())
    escaped_scan_timestamp = safe_escape(scan.created_at.strftime('%Y-%m-%d %H:%M:%S'))

    html_content = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Bug Hunter - Security Assessment</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        body {{
            font-family: 'Outfit', sans-serif;
        }}
        code, pre {{
            font-family: 'JetBrains Mono', monospace;
        }}
    </style>
</head>
<body class="bg-[#0b0f19] text-slate-200 min-h-screen">
    <!-- Navbar -->
    <header class="border-b border-slate-800/80 bg-slate-950/60 backdrop-blur sticky top-0 z-50">
        <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
            <div class="flex items-center gap-2.5">
                <div class="w-8 h-8 rounded-lg bg-gradient-to-tr from-rose-500 to-amber-500 flex items-center justify-center font-bold text-white shadow-lg shadow-rose-500/20">BH</div>
                <span class="text-xl font-bold tracking-tight bg-gradient-to-r from-rose-400 to-amber-400 bg-clip-text text-transparent">AI Bug Hunter</span>
            </div>
            <div class="flex items-center gap-3">
                <span class="text-xs font-medium text-slate-400 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-full">Assessment Scan: Confidential</span>
            </div>
        </div>
    </header>

    <main class="max-w-6xl mx-auto px-6 py-10">
        <!-- Overview Grid -->
        <section class="grid grid-cols-1 md:grid-cols-3 gap-8">
            <!-- Project Meta -->
            <div class="md:col-span-2 p-6 bg-slate-950/40 border border-slate-800/80 rounded-2xl flex flex-col justify-between">
                <div>
                    <h1 class="text-3xl font-extrabold text-slate-100 tracking-tight">{escaped_project_name}</h1>
                    <p class="mt-2 text-slate-400 text-sm leading-relaxed">{escaped_project_description}</p>
                </div>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-slate-800/80">
                    <div>
                        <span class="text-xs text-slate-500 font-bold block uppercase tracking-wider">Primary Language</span>
                        <span class="text-sm font-semibold text-slate-200 mt-0.5 block">{escaped_project_language}</span>
                    </div>
                    <div>
                        <span class="text-xs text-slate-500 font-bold block uppercase tracking-wider">Scan Upload Type</span>
                        <span class="text-sm font-semibold text-slate-200 mt-0.5 block">{escaped_project_upload_type}</span>
                    </div>
                    <div>
                        <span class="text-xs text-slate-500 font-bold block uppercase tracking-wider">Scan Triggered</span>
                        <span class="text-sm font-semibold text-slate-200 mt-0.5 block">{escaped_scan_timestamp}</span>
                    </div>
                    <div>
                        <span class="text-xs text-slate-500 font-bold block uppercase tracking-wider">Total Warnings</span>
                        <span class="text-sm font-semibold text-slate-200 mt-0.5 block">{scan.total_vulnerabilities}</span>
                    </div>
                </div>
            </div>

            <!-- Severity Counts Card -->
            <div class="p-6 bg-slate-950/40 border border-slate-800/80 rounded-2xl">
                <h2 class="text-base font-bold text-slate-300 mb-4 tracking-wide uppercase">Vulnerabilities Summary</h2>
                <div class="space-y-3">
                    <div class="flex items-center justify-between p-2.5 bg-red-950/10 border border-red-950/30 rounded-lg">
                        <span class="text-sm font-semibold text-red-400">Critical</span>
                        <span class="px-2.5 py-0.5 text-xs font-extrabold bg-red-500 text-white rounded-full">{scan.critical_count}</span>
                    </div>
                    <div class="flex items-center justify-between p-2.5 bg-orange-950/10 border border-orange-950/30 rounded-lg">
                        <span class="text-sm font-semibold text-orange-400">High</span>
                        <span class="px-2.5 py-0.5 text-xs font-extrabold bg-orange-500 text-white rounded-full">{scan.high_count}</span>
                    </div>
                    <div class="flex items-center justify-between p-2.5 bg-yellow-950/10 border border-yellow-950/30 rounded-lg">
                        <span class="text-sm font-semibold text-yellow-400">Medium</span>
                        <span class="px-2.5 py-0.5 text-xs font-extrabold bg-yellow-500 text-black rounded-full">{scan.medium_count}</span>
                    </div>
                    <div class="flex items-center justify-between p-2.5 bg-blue-950/10 border border-blue-950/30 rounded-lg">
                        <span class="text-sm font-semibold text-blue-400">Low</span>
                        <span class="px-2.5 py-0.5 text-xs font-extrabold bg-blue-500 text-white rounded-full">{scan.low_count}</span>
                    </div>
                </div>
            </div>
        </section>

        <!-- Findings List -->
        <section class="mt-10">
            <h2 class="text-2xl font-bold text-slate-100 mb-6">Identified Vulnerabilities Details</h2>
            <div class="space-y-6">
                {vuln_cards if vulnerabilities else '<div class="p-8 text-center bg-slate-900/20 border border-slate-800 rounded-xl text-slate-500">No vulnerabilities detected in this codebase. Good job!</div>'}
            </div>
        </section>
    </main>

    <footer class="mt-20 border-t border-slate-900 bg-slate-950 py-8">
        <div class="max-w-6xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-slate-500">
            <span>AI Bug Hunter Security Scan Assessment Report</span>
            <span>Generated on {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
        </div>
    </footer>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
