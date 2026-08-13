import sys
from pathlib import Path
# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.models import Scan, Project, Vulnerability
from backend.reports.pdf_gen import generate_pdf_report
import datetime

project = Project(id=1, name="TestProj", upload_type="file", owner_id=1, description="Test description")
scan = Scan(id=1, project_id=1, status="completed", total_vulnerabilities=1,
            critical_count=0, high_count=1, medium_count=0, low_count=0,
            created_at=datetime.datetime.now())

# Let's test raw unescaped values as they would come from the database/scanner
vuln = Vulnerability(
    scan_id=1,
    file_path="main.py",
    line_number=10,
    severity="HIGH",
    category="SQL Injection",
    message="Concat query execution with user input <secret>",
    tool_name="Bandit Test",
    code_snippet="if a < b:\n  print(a & b)",
    remediation="Use parameterized query",
    ai_explanation="This is a test with an unclosed <tag and a raw & character.",
    ai_fix="cursor.execute('SELECT * FROM users')"
)

try:
    generate_pdf_report(scan, project, [vuln], Path("test_report_escaped.pdf"))
    print("PDF generated successfully with escaping!")
except Exception as e:
    import traceback
    traceback.print_exc()
