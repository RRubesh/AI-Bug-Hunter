import sys
from pathlib import Path
# Add backend to sys.path
sys.path.append(r"c:\Deskop\AI Bug Hunter")

from xml.sax.saxutils import escape as xml_escape
from backend.models import Scan, Project, Vulnerability
from backend.reports.pdf_gen import generate_pdf_report
import datetime

# Mock generate_pdf_report to escape inside pdf_gen.py or let's see how we can modify pdf_gen.py.
# But for now, let's write the test case where we escape before passing, just to verify it compiles.

project = Project(id=1, name="TestProj", upload_type="file", owner_id=1, description="Test description")
scan = Scan(id=1, project_id=1, status="completed", total_vulnerabilities=1,
            critical_count=0, high_count=1, medium_count=0, low_count=0,
            created_at=datetime.datetime.now())

# Let's test escaping
ai_explanation_escaped = xml_escape("This is a test with an unclosed <tag and a raw & character.")

vuln = Vulnerability(
    scan_id=1,
    file_path="main.py",
    line_number=10,
    severity="HIGH",
    category="SQL Injection",
    message=xml_escape("Concat query execution with user input <secret>"),
    tool_name="Bandit Test",
    code_snippet=xml_escape("if a < b:\n  print(a & b)"),
    remediation=xml_escape("Use parameterized query"),
    ai_explanation=ai_explanation_escaped,
    ai_fix=xml_escape("cursor.execute('SELECT * FROM users')")
)

try:
    generate_pdf_report(scan, project, [vuln], Path("test_report_escaped.pdf"))
    print("PDF generated successfully with escaping!")
except Exception as e:
    import traceback
    traceback.print_exc()
