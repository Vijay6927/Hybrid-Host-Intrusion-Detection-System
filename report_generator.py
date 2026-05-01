"""
Report Generator for HIDS
Generates PDF and CSV reports from activity log data
"""

import csv
import io
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def generate_csv(activities: list, filter_type: str = 'all') -> bytes:
    """
    Generate a CSV report from activities.

    Args:
        activities: List of activity dicts from HIDS
        filter_type: 'all' or 'threats'

    Returns:
        CSV content as bytes
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow(['Timestamp', 'Type', 'Message', 'Status', 'Action Taken'])

    filtered = _filter_activities(activities, filter_type)

    for act in filtered:
        act_type = act.get('type', 'info').upper()
        message = act.get('message', '')
        timestamp = act.get('timestamp', '')
        action = act.get('action', '')
        status = _get_status_label(act)

        writer.writerow([timestamp, act_type, message, status, action])

    return output.getvalue().encode('utf-8-sig')  # BOM for Excel compatibility


def generate_pdf(activities: list, stats: dict, filter_type: str = 'all') -> bytes:
    """
    Generate a styled PDF report from activities.

    Args:
        activities: List of activity dicts from HIDS
        stats: Dict with summary stats (total, threats, quarantined)
        filter_type: 'all' or 'threats'

    Returns:
        PDF content as bytes
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph,
        Spacer, HRFlowable
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        title="HIDS Security Report"
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'HIDSTitle',
        parent=styles['Title'],
        fontSize=22,
        textColor=colors.HexColor('#7c3aed'),
        spaceAfter=4,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    subtitle_style = ParagraphStyle(
        'HIDSSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=16,
        alignment=TA_CENTER
    )
    section_style = ParagraphStyle(
        'HIDSSection',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor('#1e1b4b'),
        spaceBefore=12,
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    cell_style = ParagraphStyle(
        'HIDSCell',
        parent=styles['Normal'],
        fontSize=8,
        leading=10,
        wordWrap='CJK'
    )

    story = []

    # ── Title ──────────────────────────────────────────────────────────────
    story.append(Paragraph("🛡️ HIDS Security Report", title_style))
    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    filter_label = "Threats Only" if filter_type == 'threats' else "All Events"
    story.append(Paragraph(
        f"Generated: {generated_at}  |  Filter: {filter_label}",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#7c3aed'), spaceAfter=12))

    # ── Summary Stats ──────────────────────────────────────────────────────
    story.append(Paragraph("Summary", section_style))

    total = stats.get('total', len(activities))
    threats = stats.get('threats', 0)
    quarantined = stats.get('quarantined', 0)
    safe_marked = stats.get('safe_marked', 0)

    summary_data = [
        ['Total Events', 'Threats Detected', 'Quarantined', 'Marked Safe'],
        [str(total), str(threats), str(quarantined), str(safe_marked)]
    ]

    summary_table = Table(summary_data, colWidths=[6 * cm] * 4)
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e1b4b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#f1f5f9'), colors.white]),
        ('FONTSIZE', (0, 1), (-1, -1), 14),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#dc2626')),  # threats red
        ('TEXTCOLOR', (2, 1), (2, 1), colors.HexColor('#d97706')),  # quarantined amber
        ('TEXTCOLOR', (3, 1), (3, 1), colors.HexColor('#16a34a')),  # safe green
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('ROUNDEDCORNERS', [4, 4, 4, 4]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # ── Activity Table ─────────────────────────────────────────────────────
    story.append(Paragraph("Activity Log", section_style))

    filtered = _filter_activities(activities, filter_type)

    if not filtered:
        story.append(Paragraph("No activities to display.", styles['Normal']))
    else:
        # Table header
        table_data = [['#', 'Timestamp', 'Type', 'Message', 'Status']]

        for i, act in enumerate(filtered, 1):
            act_type = act.get('type', 'info').upper()
            message = act.get('message', '')
            timestamp = act.get('timestamp', '')
            status = _get_status_label(act)

            # Wrap long messages
            msg_para = Paragraph(message[:300] + ('...' if len(message) > 300 else ''), cell_style)
            table_data.append([str(i), timestamp, act_type, msg_para, status])

        col_widths = [1 * cm, 4.5 * cm, 2.5 * cm, 14 * cm, 3 * cm]
        act_table = Table(table_data, colWidths=col_widths, repeatRows=1)

        # Row colors based on type
        row_styles = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e1b4b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (2, 0), (2, -1), 'CENTER'),
            ('ALIGN', (4, 0), (4, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]

        # Alternate row backgrounds + color-code by type
        for row_idx, act in enumerate(filtered, 1):
            act_type = act.get('type', 'info')
            bg = colors.HexColor('#fff7f7') if act_type == 'threat' else (
                colors.HexColor('#f0fdf4') if act_type == 'info' else colors.HexColor('#fffbeb')
            )
            if row_idx % 2 == 0:
                bg = colors.HexColor('#f8fafc')
            row_styles.append(('BACKGROUND', (0, row_idx), (-1, row_idx), bg))

            # Color the type cell
            type_color = {
                'threat': colors.HexColor('#dc2626'),
                'warning': colors.HexColor('#d97706'),
                'info': colors.HexColor('#2563eb'),
            }.get(act_type, colors.black)
            row_styles.append(('TEXTCOLOR', (2, row_idx), (2, row_idx), type_color))
            row_styles.append(('FONTNAME', (2, row_idx), (2, row_idx), 'Helvetica-Bold'))

        act_table.setStyle(TableStyle(row_styles))
        story.append(act_table)

    # ── Footer ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#e2e8f0')))
    story.append(Paragraph(
        f"HIDS — Host Intrusion Detection System  |  Report generated {generated_at}",
        ParagraphStyle('footer', parent=styles['Normal'], fontSize=7,
                       textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER, spaceBefore=4)
    ))

    doc.build(story)
    return buffer.getvalue()


def _filter_activities(activities: list, filter_type: str) -> list:
    """Filter activities by type."""
    if filter_type == 'threats':
        return [a for a in activities if a.get('type') == 'threat']
    return activities


def _get_status_label(act: dict) -> str:
    """Return a human-readable status for an activity."""
    action = act.get('action', '')
    if action == 'deleted':
        return 'Deleted'
    elif action == 'marked_safe':
        return 'Marked Safe'
    elif action == 'quarantined':
        return 'Quarantined'
    elif act.get('type') == 'threat':
        return 'Active Threat'
    return 'Resolved'
