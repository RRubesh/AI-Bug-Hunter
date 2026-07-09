import datetime
import html
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, XPreformatted
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from backend.models import Scan, Project, Vulnerability

def safe_escape(val) -> str:
    if val is None:
        return ""
    return html.escape(str(val))

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (Skip on first page)
        if self._pageNumber > 1:
            self.drawString(54, 750, "AI Bug Hunter - Security Assessment Report")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)
            
        # Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 40, page_str)
        self.drawString(54, 40, "CONFIDENTIAL - Defensive Security Scan Report")
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(54, 52, 558, 52)
        
        self.restoreState()


def generate_pdf_report(scan: Scan, project: Project, vulnerabilities: list, output_path: Path):
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=72,
        bottomMargin=72
    )

    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=28,
        leading=34,
        textColor=colors.HexColor("#0f172a"),
        alignment=0,
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=30
    )

    h1_style = ParagraphStyle(
        "Header1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        "Header2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        "BodyTextCustom",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceAfter=8
    )

    code_style = ParagraphStyle(
        "CodeTextCustom",
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f8fafc"),
        borderColor=colors.HexColor("#e2e8f0"),
        borderWidth=0.5,
        borderPadding=6,
        spaceAfter=10
    )

    story = []

    # --- COVER PAGE ---
    story.append(Spacer(1, 40))
    story.append(Paragraph("AI Bug Hunter", title_style))
    story.append(Paragraph("Static Application Security Testing (SAST) Scan Report", subtitle_style))
    
    # Metadata Table
    meta_data = [
        [Paragraph("<b>Project Name:</b>", body_style), Paragraph(safe_escape(project.name), body_style)],
        [Paragraph("<b>Primary Language:</b>", body_style), Paragraph(safe_escape(project.language_detected or "Detecting..."), body_style)],
        [Paragraph("<b>Scan Target:</b>", body_style), Paragraph(safe_escape(project.upload_type.upper()), body_style)],
        [Paragraph("<b>Scan Triggered:</b>", body_style), Paragraph(safe_escape(scan.created_at.strftime('%Y-%m-%d %H:%M:%S')), body_style)],
        [Paragraph("<b>Total Findings:</b>", body_style), Paragraph(safe_escape(str(scan.total_vulnerabilities)), body_style)],
    ]
    meta_table = Table(meta_data, colWidths=[150, 350])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 40))

    # Executive Summary Box
    summary_text = (
        "<b>Executive Summary:</b><br/>"
        "This automated report compiles security vulnerabilities, code pattern violations, "
        "and potentially exposed hardcoded secrets in the submitted repository. "
        "For each issue, standard defensive remediation details are provided. "
        "This report is intended for defensive security operations and software engineering remediation purposes."
    )
    summary_p = Paragraph(summary_text, ParagraphStyle("SummaryBox", parent=body_style, fontSize=11, leading=15))
    summary_table = Table([[summary_p]], colWidths=[500])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
        ('RIGHTPADDING', (0,0), (-1,-1), 12),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 30))

    # Severity Matrix Table
    story.append(Paragraph("Vulnerability Severity Statistics", h2_style))
    stat_data = [
        [
            Paragraph("<b>CRITICAL</b>", ParagraphStyle("CriticalLabel", parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#ef4444"))),
            Paragraph("<b>HIGH</b>", ParagraphStyle("HighLabel", parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#f97316"))),
            Paragraph("<b>MEDIUM</b>", ParagraphStyle("MediumLabel", parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#eab308"))),
            Paragraph("<b>LOW</b>", ParagraphStyle("LowLabel", parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor("#3b82f6"))),
            Paragraph("<b>TOTAL</b>", ParagraphStyle("TotalLabel", parent=body_style, fontName="Helvetica-Bold"))
        ],
        [
            str(scan.critical_count),
            str(scan.high_count),
            str(scan.medium_count),
            str(scan.low_count),
            str(scan.total_vulnerabilities)
        ]
    ]
    stat_table = Table(stat_data, colWidths=[100, 100, 100, 100, 100])
    stat_table.setStyle(TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(stat_table)
    
    story.append(PageBreak())

    # --- DETAILED FINDINGS ---
    story.append(Paragraph("Detailed Security Findings", h1_style))
    story.append(Spacer(1, 10))

    if not vulnerabilities:
        story.append(Paragraph("No vulnerabilities were identified during the analysis.", body_style))
    else:
        # Sort vulnerabilities by severity: Critical -> High -> Medium -> Low
        severity_weight = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        vulnerabilities.sort(key=lambda v: severity_weight.get(v.severity, 4))

        for idx, vuln in enumerate(vulnerabilities, 1):
            severity_colors = {
                "CRITICAL": colors.HexColor("#ef4444"),
                "HIGH": colors.HexColor("#f97316"),
                "MEDIUM": colors.HexColor("#eab308"),
                "LOW": colors.HexColor("#3b82f6"),
                "INFO": colors.HexColor("#64748b")
            }
            sev_color = severity_colors.get(vuln.severity, colors.HexColor("#64748b"))

            # Title block
            title_p = Paragraph(f"<b>#{idx} {safe_escape(vuln.category)}</b>", ParagraphStyle("VulnTitle", parent=h2_style, textColor=colors.HexColor("#0f172a")))
            badge_p = Paragraph(f"<b>{safe_escape(vuln.severity)}</b>", ParagraphStyle("Badge", parent=body_style, textColor=sev_color, fontName="Helvetica-Bold", alignment=2))
            
            vuln_hdr_table = Table([[title_p, badge_p]], colWidths=[400, 100])
            vuln_hdr_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'BOTTOM'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(vuln_hdr_table)

            # Details
            details_text = (
                f"<b>File:</b> {safe_escape(vuln.file_path)} (Line {vuln.line_number or 'N/A'})<br/>"
                f"<b>Scanner:</b> {safe_escape(vuln.tool_name)}<br/>"
                f"<b>Description:</b> {safe_escape(vuln.message)}"
            )
            story.append(Paragraph(details_text, body_style))

            # Code block
            if vuln.code_snippet:
                story.append(XPreformatted(safe_escape(vuln.code_snippet), code_style))

            # Remediation
            remed_text = f"<b>Recommended Remediation:</b> {safe_escape(vuln.remediation)}"
            story.append(Paragraph(remed_text, body_style))

            # AI Explanation (if enriched)
            if vuln.ai_explanation:
                story.append(Paragraph("<b>AI Security Assessment:</b>", ParagraphStyle("AISecHdr", parent=body_style, fontName="Helvetica-Bold")))
                escaped_explanation = safe_escape(vuln.ai_explanation).replace("\n", "<br/>")
                story.append(Paragraph(escaped_explanation, body_style))
                if vuln.ai_fix:
                    story.append(Paragraph("<b>AI Secure Implementation Recommendation:</b>", ParagraphStyle("AISecHdr2", parent=body_style, fontName="Helvetica-Bold")))
                    story.append(XPreformatted(safe_escape(vuln.ai_fix), code_style))

            # Divider Line
            divider = Table([[""]], colWidths=[500])
            divider.setStyle(TableStyle([
                ('LINEBELOW', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
                ('BOTTOMPADDING', (0,0), (-1,-1), 10),
                ('TOPPADDING', (0,0), (-1,-1), 10),
            ]))
            story.append(divider)
            story.append(Spacer(1, 10))

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
