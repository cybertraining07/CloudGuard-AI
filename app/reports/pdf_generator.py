import json
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def generate_pdf_report(report_path):
    source = Path(report_path)

    if not source.is_file():
        raise FileNotFoundError(f"Report not found: {source}")

    with source.open("r", encoding="utf-8") as file:
        report = json.load(file)

    pdf_path = source.with_suffix(".pdf")

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#17365D"),
        alignment=TA_CENTER,
        spaceAfter=15
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#17365D"),
        spaceBefore=14,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11
    )

    def paragraph(value):
        return Paragraph(escape(str(value or "N/A")), body_style)

    def make_table(headers, rows, widths):
        data = [[paragraph(item) for item in headers]]

        for row in rows:
            data.append([paragraph(item) for item in row])

        table = Table(
            data,
            colWidths=widths,
            repeatRows=1,
            hAlign="LEFT"
        )

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0),
             colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F1F5F9")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        return table

    story = []

    results = report.get("results", {})
    summary = report.get("assessment_summary", {})

    story.append(Paragraph(
        "CloudGuard AI Security Assessment",
        title_style
    ))

    story.append(Paragraph(
        "Cloud Security Posture and Attack Path Analysis",
        ParagraphStyle(
            "Subtitle",
            parent=body_style,
            alignment=TA_CENTER,
            fontSize=10
        )
    ))

    story.append(Spacer(1, 15))

    story.append(Paragraph("Assessment Information", heading_style))

    story.append(make_table(
        ["Field", "Value"],
        [
            ["Project", report.get("project", "CloudGuard AI")],
            ["Report", report.get("report_title", "Security Assessment")],
            ["Generated", report.get("generated_at", "N/A")],
            ["Source JSON", source.name],
        ],
        [1.5 * inch, 5 * inch]
    ))

    story.append(Paragraph("Executive Summary", heading_style))

    story.append(make_table(
        ["Metric", "Total"],
        [
            ["Cloud findings", summary.get("cloud_findings", 0)],
            ["IAM findings", summary.get("iam_findings", 0)],
            ["Attack paths detected", summary.get("attack_paths_detected", 0)],
            ["Prioritized findings", summary.get("prioritized_findings", 0)],
            ["Recommendations generated",
             summary.get("recommendations_generated", 0)],
        ],
        [3 * inch, 3.5 * inch]
    ))

    risk_findings = results.get("risk_analysis", {}).get("findings", [])

    story.append(Paragraph("Prioritized Security Findings", heading_style))

    risk_rows = []

    for finding in risk_findings:
        risk_rows.append([
            finding.get("severity", "N/A"),
            finding.get("risk_score", "N/A"),
            finding.get("priority", "N/A"),
            finding.get("issue") or finding.get("identity")
            or finding.get("resource_id") or "Security finding",
            finding.get("recommendation", "Review finding")
        ])

    if risk_rows:
        story.append(make_table(
            ["Severity", "Score", "Priority", "Finding", "Recommendation"],
            risk_rows,
            [0.8 * inch, 0.5 * inch, 0.8 * inch, 1.8 * inch, 2.1 * inch]
        ))
    else:
        story.append(paragraph("No prioritized findings were recorded."))

    cloud_findings = results.get("cloud_scan", {}).get("findings", [])

    story.append(Paragraph("Cloud Security Findings", heading_style))

    cloud_rows = [
        [
            item.get("resource_id", "N/A"),
            item.get("severity", "N/A"),
            item.get("issue", "N/A"),
            item.get("recommendation", "N/A")
        ]
        for item in cloud_findings
    ]

    if cloud_rows:
        story.append(make_table(
            ["Resource", "Severity", "Issue", "Recommendation"],
            cloud_rows,
            [1.3 * inch, 0.8 * inch, 1.7 * inch, 2.2 * inch]
        ))
    else:
        story.append(paragraph("No cloud findings recorded."))

    iam_findings = results.get("iam_analysis", {}).get("findings", [])

    story.append(Paragraph("Identity and Access Management Findings", heading_style))

    iam_rows = [
        [
            item.get("username", "N/A"),
            item.get("severity", "N/A"),
            item.get("issue", "N/A"),
            item.get("recommendation", "N/A")
        ]
        for item in iam_findings
    ]

    if iam_rows:
        story.append(make_table(
            ["Username", "Severity", "Issue", "Recommendation"],
            iam_rows,
            [1.2 * inch, 0.8 * inch, 2 * inch, 2 * inch]
        ))
    else:
        story.append(paragraph("No IAM findings recorded."))

    attack_paths = results.get(
        "attack_path_analysis", {}
    ).get("attack_paths", [])

    story.append(Paragraph("Attack Path Analysis", heading_style))

    attack_rows = [
        [
            item.get("identity", "N/A"),
            item.get("target_resource", "N/A"),
            item.get("severity", "N/A"),
            " -> ".join(item.get("attack_path", [])),
        ]
        for item in attack_paths
    ]

    if attack_rows:
        story.append(make_table(
            ["Identity", "Target", "Severity", "Attack Path"],
            attack_rows,
            [1.2 * inch, 1.5 * inch, 0.8 * inch, 2.5 * inch]
        ))
    else:
        story.append(paragraph("No attack paths detected."))

    recommendations = results.get(
        "recommendations", {}
    ).get("recommendations", [])

    story.append(Paragraph("Remediation Recommendations", heading_style))

    recommendation_rows = [
        [
            item.get("severity", "N/A"),
            item.get("issue", "N/A"),
            item.get("recommended_action", "N/A"),
            item.get("verification_steps", "N/A")
        ]
        for item in recommendations
    ]

    if recommendation_rows:
        story.append(make_table(
            ["Severity", "Issue", "Recommended Action", "Verification"],
            recommendation_rows,
            [0.8 * inch, 1.3 * inch, 2.2 * inch, 1.7 * inch]
        ))
    else:
        story.append(paragraph("No recommendations recorded."))

    story.append(Spacer(1, 20))

    story.append(Paragraph(
        "Generated by CloudGuard AI. This report reflects the "
        "assessment data supplied to the application. Findings should "
        "be independently validated before remediation decisions.",
        body_style
    ))

    document = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        title="CloudGuard AI Security Assessment"
    )

    document.build(story)

    return str(pdf_path)
