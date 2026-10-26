from datetime import datetime, timezone
from html import escape
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from models import Scenario


def _paragraph(value: object, style: ParagraphStyle) -> Paragraph:
    safe_text = escape(str(value)).replace("\n", "<br/>")
    return Paragraph(safe_text, style)


def _report_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=29,
            textColor=colors.HexColor("#14213d"),
            spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#2f6fed"),
            spaceAfter=14,
        ),
        "section": ParagraphStyle(
            "ReportSection",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=colors.HexColor("#14213d"),
            spaceBefore=16,
            spaceAfter=8,
            keepWithNext=True,
        ),
        "subheading": ParagraphStyle(
            "ReportSubheading",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=colors.HexColor("#344054"),
            spaceBefore=10,
            spaceAfter=5,
            keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.2,
            leading=13.2,
            textColor=colors.HexColor("#344054"),
            spaceAfter=6,
            wordWrap="CJK",
        ),
        "small": ParagraphStyle(
            "ReportSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.8,
            leading=10.5,
            textColor=colors.HexColor("#475467"),
            wordWrap="CJK",
        ),
        "table_header": ParagraphStyle(
            "ReportTableHeader",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.8,
            leading=10,
            textColor=colors.white,
            alignment=TA_CENTER,
            wordWrap="CJK",
        ),
        "empty": ParagraphStyle(
            "ReportEmpty",
            parent=base["BodyText"],
            fontName="Helvetica-Oblique",
            fontSize=9.2,
            leading=13.2,
            textColor=colors.HexColor("#667085"),
            leftIndent=10,
            borderColor=colors.HexColor("#dde4ee"),
            borderWidth=0.5,
            borderPadding=8,
            backColor=colors.HexColor("#f8fafc"),
            spaceAfter=8,
        ),
    }


def _styled_table(
    rows: list[list[object]],
    column_widths: list[float],
) -> Table:
    table = Table(
        rows,
        colWidths=column_widths,
        repeatRows=1,
        splitByRow=1,
        splitInRow=1,
        hAlign="LEFT",
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14213d")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d5dd")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.white,
                    colors.HexColor("#f8fafc"),
                ]),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _connection_table(
    connections: list[dict[str, object]],
    styles: dict[str, ParagraphStyle],
    page_width: float,
) -> Table | Paragraph:
    if not connections:
        return _paragraph("No connection evidence is available.", styles["empty"])

    rows = [
        [
            _paragraph("Source", styles["table_header"]),
            _paragraph("Target", styles["table_header"]),
            _paragraph("Connection", styles["table_header"]),
            _paragraph("Reason", styles["table_header"]),
        ]
    ]
    for connection in connections:
        rows.append(
            [
                _paragraph(
                    f'{connection["source_name"]} '
                    f'({connection["source_id"]})',
                    styles["small"],
                ),
                _paragraph(
                    f'{connection["target_name"]} '
                    f'({connection["target_id"]})',
                    styles["small"],
                ),
                _paragraph(
                    f'{connection["protocol"]}/{connection["port"]}',
                    styles["small"],
                ),
                _paragraph(connection["reason"], styles["small"]),
            ]
        )
    return _styled_table(
        rows,
        [page_width * 0.25, page_width * 0.25, page_width * 0.15, page_width * 0.35],
    )


def _draw_page_footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setTitle("Cloud Security Visualiser - Security Assessment Report")
    canvas.setAuthor("Cloud Security Visualiser")
    canvas.setStrokeColor(colors.HexColor("#d0d5dd"))
    canvas.line(
        document.leftMargin,
        0.48 * inch,
        letter[0] - document.rightMargin,
        0.48 * inch,
    )
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#667085"))
    canvas.drawString(
        document.leftMargin,
        0.3 * inch,
        "Cloud Security Visualiser - simplified model assessment",
    )
    canvas.drawRightString(
        letter[0] - document.rightMargin,
        0.3 * inch,
        f"Page {document.page}",
    )
    canvas.restoreState()


def generate_security_report(
    scenario: Scenario,
    remediation_result: dict[str, object],
) -> bytes:
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.58 * inch,
        leftMargin=0.58 * inch,
        topMargin=0.58 * inch,
        bottomMargin=0.68 * inch,
        title="Cloud Security Visualiser - Security Assessment Report",
        author="Cloud Security Visualiser",
    )
    styles = _report_styles()
    story = []
    node_names = {node.id: node.name for node in scenario.nodes}
    original_scan = remediation_result["original_scan"]
    verification_scan = remediation_result["verification_scan"]
    before_after = remediation_result["before_after"]
    changes = remediation_result["changes"]
    residual_explanations = remediation_result["residual_explanations"]
    path_explanations = remediation_result["remaining_path_explanations"]
    status_label = (
        "Residual risks remain"
        if remediation_result["security_status"] == "residual_risks"
        else "No detected risks remain"
    )

    story.extend(
        [
            _paragraph("Cloud Security Visualiser", styles["subtitle"]),
            _paragraph("Security Assessment Report", styles["title"]),
            _paragraph(
                f"Scenario: {scenario.name} ({scenario.id})",
                styles["body"],
            ),
            _paragraph(
                "Generated: "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                styles["body"],
            ),
            _paragraph(
                "This report analyzes a simplified user-provided JSON "
                "infrastructure model. It is not an assessment of a connected "
                "or deployed cloud account.",
                styles["empty"],
            ),
        ]
    )

    story.append(_paragraph("1. Infrastructure Overview", styles["section"]))
    story.append(_paragraph(scenario.description, styles["body"]))
    story.append(
        _paragraph(
            f"Resources: {len(scenario.nodes)} | Original connections: "
            f"{len(scenario.edges)}",
            styles["body"],
        )
    )
    resource_rows = [
        [
            _paragraph("Resource ID", styles["table_header"]),
            _paragraph("Name", styles["table_header"]),
            _paragraph("Type", styles["table_header"]),
            _paragraph("Public", styles["table_header"]),
            _paragraph("Sensitive", styles["table_header"]),
        ]
    ]
    resource_rows.extend(
        [
            _paragraph(node.id, styles["small"]),
            _paragraph(node.name, styles["small"]),
            _paragraph(node.type, styles["small"]),
            _paragraph("Yes" if node.public else "No", styles["small"]),
            _paragraph("Yes" if node.sensitive else "No", styles["small"]),
        ]
        for node in scenario.nodes
    )
    story.append(
        _styled_table(
            resource_rows,
            [
                document.width * 0.22,
                document.width * 0.32,
                document.width * 0.18,
                document.width * 0.14,
                document.width * 0.14,
            ],
        )
    )

    story.append(_paragraph("2. Initial Security Findings", styles["section"]))
    original_summary = original_scan["summary"]
    story.append(
        _paragraph(
            f'Total: {original_summary["total_findings"]} | '
            f'High: {original_summary["high"]} | '
            f'Critical: {original_summary["critical"]}',
            styles["body"],
        )
    )
    if not original_scan["findings"]:
        story.append(
            _paragraph(
                "No initial security findings were detected by the currently "
                "implemented rules.",
                styles["empty"],
            )
        )
    for index, finding in enumerate(original_scan["findings"], start=1):
        story.append(
            _paragraph(
                f"Finding {index}: {node_names[finding.resource]} "
                f"({finding.resource}) - {finding.severity.upper()}",
                styles["subheading"],
            )
        )
        story.append(_paragraph(finding.explanation, styles["body"]))
        story.append(
            _paragraph(
                f"Existing recommendation: {finding.remediation}",
                styles["body"],
            )
        )

    story.append(_paragraph("3. Proposed Security Changes", styles["section"]))
    if not changes:
        story.append(
            _paragraph(
                "No security changes were proposed by the supported one-pass "
                "remediation engine.",
                styles["empty"],
            )
        )
    for index, change in enumerate(changes, start=1):
        story.append(
            _paragraph(
                f'Change {index}: {change["source_node_id"]} -> '
                f'{change["target_node_id"]}',
                styles["subheading"],
            )
        )
        story.append(
            _paragraph(
                f'Connection: {change["protocol"]}/{change["port"]} | '
                f'Action: {str(change["proposed_action"]).replace("_", " ")} | '
                "Security risk: "
                f'{str(change["associated_security_risk"]).replace("_", " ")}',
                styles["body"],
            )
        )
        story.append(_paragraph(f'Reason: {change["reason"]}', styles["body"]))
        story.append(
            _paragraph(
                "Potential operational impact: "
                f'{change["potential_operational_impact"]}',
                styles["body"],
            )
        )

    story.append(_paragraph("4. Verification Results", styles["section"]))
    verification_summary = verification_scan["summary"]
    verification_rows = [
        [
            _paragraph("Initial findings", styles["table_header"]),
            _paragraph("Remaining findings", styles["table_header"]),
            _paragraph("Proposed changes", styles["table_header"]),
            _paragraph("Final supported-risk status", styles["table_header"]),
        ],
        [
            _paragraph(before_after["initial_findings"], styles["small"]),
            _paragraph(before_after["remaining_findings"], styles["small"]),
            _paragraph(len(changes), styles["small"]),
            _paragraph(status_label, styles["small"]),
        ],
    ]
    story.append(
        _styled_table(
            verification_rows,
            [
                document.width * 0.2,
                document.width * 0.2,
                document.width * 0.2,
                document.width * 0.4,
            ],
        )
    )
    story.append(Spacer(1, 7))
    story.append(
        _paragraph(
            f'Post-remediation severity breakdown - High: '
            f'{verification_summary["high"]} | Critical: '
            f'{verification_summary["critical"]} | Potential attack paths: '
            f'{verification_summary["attack_paths"]}',
            styles["body"],
        )
    )

    story.append(_paragraph("5. Detailed Residual Findings", styles["section"]))
    if not residual_explanations:
        story.append(
            _paragraph(
                "No residual findings remain after the verification scan.",
                styles["empty"],
            )
        )
    for index, explanation in enumerate(residual_explanations, start=1):
        resource = explanation["affected_resource"]
        story.append(
            _paragraph(
                f'Residual finding {index}: {resource["name"]} '
                f'({resource["id"]}) - {str(explanation["severity"]).upper()}',
                styles["subheading"],
            )
        )
        story.append(
            _paragraph(explanation["finding_explanation"], styles["body"])
        )
        story.append(_paragraph("Connection evidence", styles["subheading"]))
        story.append(
            _connection_table(
                explanation["connection_evidence"], styles, document.width
            )
        )
        story.append(Spacer(1, 5))
        story.append(
            _paragraph(
                f'Why the finding remains: {explanation["why_risk_remains"]}',
                styles["body"],
            )
        )
        story.append(
            _paragraph(
                "Why it was not automatically remediated: "
                f'{explanation["why_not_remediated"]}',
                styles["body"],
            )
        )
        story.append(
            _paragraph(
                "Recommended manual mitigation: "
                f'{explanation["recommended_manual_mitigation"]}',
                styles["body"],
            )
        )
        story.append(
            _paragraph(
                "Potential operational impact: "
                f'{explanation["potential_operational_impact"]}',
                styles["body"],
            )
        )

    story.append(
        _paragraph("6. Remaining Potential Attack Paths", styles["section"])
    )
    if not path_explanations:
        story.append(
            _paragraph(
                "No remaining potential attack paths were detected by the "
                "current analyzer.",
                styles["empty"],
            )
        )
    for path_index, path in enumerate(path_explanations, start=1):
        story.append(
            _paragraph(
                f'Path {path_index}: {" -> ".join(path["resource_names"])}',
                styles["subheading"],
            )
        )
        story.append(
            _paragraph(
                f'Ordered node IDs: {" -> ".join(path["node_ids"])}',
                styles["body"],
            )
        )
        for hop_index, hop in enumerate(path["hops"], start=1):
            story.append(
                _paragraph(
                    f'Hop {hop_index}: {hop["source_name"]} '
                    f'({hop["source_id"]}) -> {hop["target_name"]} '
                    f'({hop["target_id"]})',
                    styles["subheading"],
                )
            )
            story.append(
                _connection_table(hop["connections"], styles, document.width)
            )
        story.append(Spacer(1, 5))
        story.append(
            _paragraph(
                f'Why the path remains: {path["why_path_remains"]}',
                styles["body"],
            )
        )
        story.append(
            _paragraph(
                f'Why remediation stopped: {path["why_remediation_stopped"]}',
                styles["body"],
            )
        )
        story.append(
            _paragraph(
                f'Manual recommendation: {path["manual_mitigation"]}',
                styles["body"],
            )
        )
        story.append(
            _paragraph(
                f'Potential operational impact: {path["potential_operational_impact"]}',
                styles["body"],
            )
        )

    story.append(_paragraph("7. Security Limitations", styles["section"]))
    limitations = [
        "The system analyzes simplified user-provided JSON infrastructure.",
        "It does not connect to real cloud accounts or inspect deployed resources.",
        "It does not modify deployed cloud infrastructure.",
        "Remediation proposals are generated from a copy of the configuration.",
        "The remediation engine performs only one pass.",
        "Only the currently implemented security rules are evaluated.",
        "The current analyzer may report only one potential attack path.",
        "No detected risks does not guarantee universal security.",
        "Potential attack paths indicate modeled network reachability, not "
        "successful exploitation or confirmed compromise.",
    ]
    for limitation in limitations:
        story.append(_paragraph(f"- {limitation}", styles["body"]))

    document.build(
        story,
        onFirstPage=_draw_page_footer,
        onLaterPages=_draw_page_footer,
    )
    return buffer.getvalue()
