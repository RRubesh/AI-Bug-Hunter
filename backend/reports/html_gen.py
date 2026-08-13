import datetime
import html
from pathlib import Path
from backend.models import Scan, Project, Vulnerability

def safe_escape(val) -> str:
    if val is None:
        return ""
    return html.escape(str(val))

def format_markdown_text(val: str) -> str:
    if not val:
        return ""
    import re
    text = html.escape(str(val))
    text = re.sub(r'#{1,6}\s*(.*?)(?=\n|$)', r'<strong class="block text-slate-100 mt-2 mb-1">\1</strong>', text)
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'`([^`]+)`', r'<code class="px-1 py-0.5 bg-slate-900 rounded text-emerald-300 font-mono text-xs">\1</code>', text)
    return text

def build_vuln_card(idx: int, vuln: Vulnerability) -> str:
    sev_badge_color = {
        "CRITICAL": "bg-red-500/10 text-red-500 border border-red-500/20",
        "HIGH": "bg-orange-500/10 text-orange-500 border border-orange-500/20",
        "MEDIUM": "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20",
        "LOW": "bg-blue-500/10 text-blue-500 border border-blue-500/20",
        "INFO": "bg-slate-500/10 text-slate-400 border border-slate-500/20"
    }.get(vuln.severity, "bg-slate-500/10 text-slate-400")

    escaped_code_snippet = safe_escape(vuln.code_snippet)
    formatted_ai_explanation = format_markdown_text(vuln.ai_explanation)
    formatted_ai_fix = format_markdown_text(vuln.ai_fix)
    escaped_severity = safe_escape(vuln.severity)
    escaped_category = safe_escape(vuln.category)
    escaped_file_path = safe_escape(vuln.file_path)
    escaped_tool_name = safe_escape(vuln.tool_name)
    escaped_message = safe_escape(vuln.message)
    escaped_remediation = safe_escape(vuln.remediation)

    code_snippet_html = ""
    if vuln.code_snippet:
        code_snippet_html = (
            '<div class="mt-3">'
            '<span class="text-xs font-semibold text-slate-400">Vulnerable Code Snippet:</span>'
            '<pre class="mt-1 p-3 bg-slate-900 border border-slate-700/50 rounded-md overflow-x-auto">'
            '<code class="text-xs text-slate-300 font-mono">{code}</code></pre>'
            '</div>'
        ).format(code=escaped_code_snippet)

    ai_fix_html = ""
    if vuln.ai_fix:
        ai_fix_html = (
            '<div class="mt-3">'
            '<span class="text-xs font-semibold text-emerald-400">AI Secure Implementation:</span>'
            '<pre class="mt-1 p-3 bg-emerald-950/20 border border-emerald-900/30 rounded-md overflow-x-auto">'
            '<code class="text-xs text-emerald-300 font-mono">{fix}</code></pre>'
            '</div>'
        ).format(fix=formatted_ai_fix)

    ai_analysis_html = ""
    if vuln.ai_explanation:
        ai_analysis_html = (
            '<div class="mt-4 pt-4 border-t border-slate-800">'
            '<span class="text-xs font-semibold text-emerald-400 flex items-center gap-1.5">'
            '<svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path></svg>'
            'AI Security Assessment:'
            '</span>'
            '<div class="mt-1 text-sm text-slate-300 whitespace-pre-line leading-relaxed">{exp}</div>'
            '{fix_html}'
            '</div>'
        ).format(exp=formatted_ai_explanation, fix_html=ai_fix_html)

    line_num_str = ": Line {}".format(vuln.line_number) if vuln.line_number else ""

    card_template = (
        '<div class="p-6 bg-slate-800/40 border border-slate-800 rounded-xl hover:border-slate-700/80 transition-all duration-200">'
        '<div class="flex flex-wrap items-start justify-between gap-4">'
        '<div>'
        '<div class="flex items-center gap-3">'
        '<span class="px-2.5 py-0.5 text-xs font-bold rounded-full {badge_color}">{sev}</span>'
        '<h3 class="text-lg font-bold text-slate-100">#{idx} {cat}</h3>'
        '</div>'
        '<p class="mt-1.5 text-xs text-slate-400 font-mono">{file_path} {line_str}</p>'
        '</div>'
        '<div class="text-right">'
        '<span class="text-xs text-slate-500 font-semibold bg-slate-900 px-2.5 py-1 rounded-md border border-slate-800">{tool}</span>'
        '</div>'
        '</div>'
        '<p class="mt-3 text-sm text-slate-300">{msg}</p>'
        '{snippet_html}'
        '<div class="mt-3 bg-slate-900/40 border border-slate-800 p-3 rounded-lg">'
        '<span class="text-xs font-semibold text-slate-400">Remediation Guide:</span>'
        '<p class="mt-0.5 text-sm text-slate-300">{remediation}</p>'
        '</div>'
        '{ai_html}'
        '</div>'
    )

    return card_template.format(
        badge_color=sev_badge_color,
        sev=escaped_severity,
        idx=idx,
        cat=escaped_category,
        file_path=escaped_file_path,
        line_str=line_num_str,
        tool=escaped_tool_name,
        msg=escaped_message,
        snippet_html=code_snippet_html,
        remediation=escaped_remediation,
        ai_html=ai_analysis_html
    )


def generate_html_report(scan: Scan, project: Project, vulnerabilities: list, output_path: Path):
    # Sort vulnerabilities by severity: Critical -> High -> Medium -> Low
    severity_weight = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_weight.get(v.severity, 4))
    
    vuln_cards = "".join(build_vuln_card(idx, vuln) for idx, vuln in enumerate(sorted_vulns, 1))

    escaped_project_name = safe_escape(project.name)
    escaped_project_description = safe_escape(project.description or 'Static security scan and code analysis summary.')
    escaped_project_language = safe_escape(project.language_detected or 'Unknown')
    escaped_project_upload_type = safe_escape(project.upload_type.upper() if project.upload_type else 'FILE')
    escaped_scan_timestamp = safe_escape(scan.created_at.strftime('%Y-%m-%d %H:%M:%S') if scan.created_at else '')

    cards_section_html = vuln_cards if sorted_vulns else '<div class="p-8 text-center bg-slate-900/20 border border-slate-800 rounded-xl text-slate-500">No vulnerabilities detected in this codebase. Good job!</div>'
    generated_time = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    page_template = (
        '<!DOCTYPE html>\n'
        '<html lang="en" class="dark">\n'
        '<head>\n'
        '    <meta charset="UTF-8">\n'
        '    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        '    <title>AI Bug Hunter - Security Assessment</title>\n'
        '    <script src="https://cdn.tailwindcss.com"></script>\n'
        '    <style>\n'
        '        @import url(\'https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap\');\n'
        '        body {\n'
        '            font-family: \'Outfit\', sans-serif;\n'
        '        }\n'
        '        code, pre {\n'
        '            font-family: \'JetBrains Mono\', monospace;\n'
        '        }\n'
        '    </style>\n'
        '</head>\n'
        '<body class="bg-[#0b0f19] text-slate-200 min-h-screen">\n'
        '    <!-- Navbar -->\n'
        '    <header class="border-b border-slate-800/80 bg-slate-950/60 backdrop-blur sticky top-0 z-50">\n'
        '        <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">\n'
        '            <div class="flex items-center gap-2.5">\n'
        '                <div class="w-8 h-8 rounded-lg bg-gradient-to-tr from-rose-500 to-amber-500 flex items-center justify-center font-bold text-white shadow-lg shadow-rose-500/20">BH</div>\n'
        '                <span class="text-xl font-bold tracking-tight bg-gradient-to-r from-rose-400 to-amber-400 bg-clip-text text-transparent">AI Bug Hunter</span>\n'
        '            </div>\n'
        '            <div class="flex items-center gap-3">\n'
        '                <span class="text-xs font-medium text-slate-400 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-full">Assessment Scan: Confidential</span>\n'
        '            </div>\n'
        '        </div>\n'
        '    </header>\n'
        '\n'
        '    <main class="max-w-6xl mx-auto px-6 py-10">\n'
        '        <!-- Overview Grid -->\n'
        '        <section class="grid grid-cols-1 md:grid-cols-3 gap-8">\n'
        '            <!-- Project Meta -->\n'
        '            <div class="md:col-span-2 p-6 bg-slate-950/40 border border-slate-800/80 rounded-2xl flex flex-col justify-between">\n'
        '                <div>\n'
        '                    <h1 class="text-3xl font-extrabold text-slate-100 tracking-tight">{project_name}</h1>\n'
        '                    <p class="mt-2 text-slate-400 text-sm leading-relaxed">{project_desc}</p>\n'
        '                </div>\n'
        '                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-slate-800/80">\n'
        '                    <div>\n'
        '                        <span class="text-xs text-slate-500 font-bold block uppercase tracking-wider">Primary Language</span>\n'
        '                        <span class="text-sm font-semibold text-slate-200 mt-0.5 block">{project_lang}</span>\n'
        '                    </div>\n'
        '                    <div>\n'
        '                        <span class="text-xs text-slate-500 font-bold block uppercase tracking-wider">Scan Upload Type</span>\n'
        '                        <span class="text-sm font-semibold text-slate-200 mt-0.5 block">{upload_type}</span>\n'
        '                    </div>\n'
        '                    <div>\n'
        '                        <span class="text-xs text-slate-500 font-bold block uppercase tracking-wider">Scan Triggered</span>\n'
        '                        <span class="text-sm font-semibold text-slate-200 mt-0.5 block">{timestamp}</span>\n'
        '                    </div>\n'
        '                    <div>\n'
        '                        <span class="text-xs text-slate-500 font-bold block uppercase tracking-wider">Total Warnings</span>\n'
        '                        <span class="text-sm font-semibold text-slate-200 mt-0.5 block">{total_warnings}</span>\n'
        '                    </div>\n'
        '                </div>\n'
        '            </div>\n'
        '\n'
        '            <!-- Severity Counts Card -->\n'
        '            <div class="p-6 bg-slate-950/40 border border-slate-800/80 rounded-2xl">\n'
        '                <h2 class="text-base font-bold text-slate-300 mb-4 tracking-wide uppercase">Vulnerabilities Summary</h2>\n'
        '                <div class="space-y-3">\n'
        '                    <div class="flex items-center justify-between p-2.5 bg-red-950/10 border border-red-950/30 rounded-lg">\n'
        '                        <span class="text-sm font-semibold text-red-400">Critical</span>\n'
        '                        <span class="px-2.5 py-0.5 text-xs font-extrabold bg-red-500 text-white rounded-full">{critical_count}</span>\n'
        '                    </div>\n'
        '                    <div class="flex items-center justify-between p-2.5 bg-orange-950/10 border border-orange-950/30 rounded-lg">\n'
        '                        <span class="text-sm font-semibold text-orange-400">High</span>\n'
        '                        <span class="px-2.5 py-0.5 text-xs font-extrabold bg-orange-500 text-white rounded-full">{high_count}</span>\n'
        '                    </div>\n'
        '                    <div class="flex items-center justify-between p-2.5 bg-yellow-950/10 border border-yellow-950/30 rounded-lg">\n'
        '                        <span class="text-sm font-semibold text-yellow-400">Medium</span>\n'
        '                        <span class="px-2.5 py-0.5 text-xs font-extrabold bg-yellow-500 text-black rounded-full">{medium_count}</span>\n'
        '                    </div>\n'
        '                    <div class="flex items-center justify-between p-2.5 bg-blue-950/10 border border-blue-950/30 rounded-lg">\n'
        '                        <span class="text-sm font-semibold text-blue-400">Low</span>\n'
        '                        <span class="px-2.5 py-0.5 text-xs font-extrabold bg-blue-500 text-white rounded-full">{low_count}</span>\n'
        '                    </div>\n'
        '                </div>\n'
        '            </div>\n'
        '        </section>\n'
        '\n'
        '        <!-- Findings List -->\n'
        '        <section class="mt-10">\n'
        '            <h2 class="text-2xl font-bold text-slate-100 mb-6">Identified Vulnerabilities Details</h2>\n'
        '            <div class="space-y-6">\n'
        '                {cards_content}\n'
        '            </div>\n'
        '        </section>\n'
        '    </main>\n'
        '\n'
        '    <footer class="mt-20 border-t border-slate-900 bg-slate-950 py-8">\n'
        '        <div class="max-w-6xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4 text-xs text-slate-500">\n'
        '            <span>AI Bug Hunter Security Scan Assessment Report</span>\n'
        '            <span>Generated on {generated_time}</span>\n'
        '        </div>\n'
        '    </footer>\n'
        '</body>\n'
        '</html>\n'
    )

    html_content = page_template.format(
        project_name=escaped_project_name,
        project_desc=escaped_project_description,
        project_lang=escaped_project_language,
        upload_type=escaped_project_upload_type,
        timestamp=escaped_scan_timestamp,
        total_warnings=scan.total_vulnerabilities,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        cards_content=cards_section_html,
        generated_time=generated_time
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


