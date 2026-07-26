import os
import uuid
import qrcode
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                  TableStyle, HRFlowable, Image)
from reportlab.graphics.shapes import Drawing, Rect, Circle, String
from reportlab.graphics import renderPDF

CERTS_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'generated_certificates')

# ── Colors ────────────────────────────────────────────────────────────────────
GOV_DARK   = colors.HexColor('#2C4A7C')
GOV_MID    = colors.HexColor('#4A6FA5')
GOV_LIGHT  = colors.HexColor('#6C8EBF')
GOV_BG     = colors.HexColor('#EBF2FF')
GOLD       = colors.HexColor('#C9A84C')
GOLD_LIGHT = colors.HexColor('#F5E6C0')
TEXT_DARK  = colors.HexColor('#1a2332')
TEXT_GREY  = colors.HexColor('#6b7a8d')
WHITE      = colors.white
GREEN      = colors.HexColor('#15803d')


def _generate_qr(content: str) -> Image:
    qr = qrcode.QRCode(version=2, box_size=4, border=2,
                        error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(content)
    qr.make(fit=True)
    img = qr.make_image(fill_color='#2C4A7C', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return Image(buf, width=2.8*cm, height=2.8*cm)


def _seal_drawing() -> Drawing:
    """Simple vector government seal."""
    d = Drawing(80, 80)
    # Outer ring
    d.add(Circle(40, 40, 38, fillColor=GOV_DARK, strokeColor=GOLD, strokeWidth=2))
    # Inner ring
    d.add(Circle(40, 40, 30, fillColor=GOV_MID, strokeColor=GOLD_LIGHT, strokeWidth=1))
    # Star-like centre
    d.add(Circle(40, 40, 16, fillColor=GOLD, strokeColor=WHITE, strokeWidth=1))
    # Text on outer ring (top arc label)
    d.add(String(14, 54, 'NEPAL', fontName='Helvetica-Bold', fontSize=7, fillColor=GOLD))
    d.add(String(10, 22, 'GOVERNMENT', fontName='Helvetica-Bold', fontSize=6, fillColor=GOLD))
    # Centre initials
    d.add(String(33, 35, 'NP', fontName='Helvetica-Bold', fontSize=12, fillColor=WHITE))
    return d


def generate_approval_certificate(appl: dict, citizen: dict, officer: dict,
                                   citizenship_number: str = '') -> tuple[str, str]:
    """
    Generate a government-style PDF approval certificate.
    Returns (certificate_number, pdf_filename).
    """
    os.makedirs(CERTS_FOLDER, exist_ok=True)

    cert_number = f"CERT-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    pdf_filename = f"{cert_number}.pdf"
    pdf_path = os.path.join(CERTS_FOLDER, pdf_filename)

    service_labels = {
        'driving_license': 'Driving License Application',
        'business_registration': 'Business Registration',
        'tax_filing': 'Income Tax Filing',
    }
    service_label = service_labels.get(appl['service_type'], appl['service_type'].replace('_', ' ').title())
    approval_date = datetime.utcnow().strftime('%B %d, %Y')
    issued_time   = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=1.8*cm, leftMargin=1.8*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
    )

    styles = getSampleStyleSheet()
    story  = []

    # ── Helper styles ─────────────────────────────────────────────────────────
    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    s_system = ps('sys', fontName='Helvetica', fontSize=7.5, textColor=GOV_LIGHT,
                  alignment=TA_CENTER, spaceAfter=1)
    s_govt   = ps('govt', fontName='Helvetica-Bold', fontSize=13, textColor=WHITE,
                  alignment=TA_CENTER)
    s_dept   = ps('dept', fontName='Helvetica', fontSize=9, textColor=GOLD_LIGHT,
                  alignment=TA_CENTER)
    s_cert_h = ps('certh', fontName='Helvetica-Bold', fontSize=22, textColor=GOLD,
                  alignment=TA_CENTER, spaceAfter=2)
    s_cert_s = ps('certs', fontName='Helvetica', fontSize=10, textColor=GOV_LIGHT,
                  alignment=TA_CENTER, spaceAfter=6)
    s_body   = ps('body', fontName='Helvetica', fontSize=10, textColor=TEXT_DARK,
                  leading=16, spaceAfter=6, alignment=TA_JUSTIFY)
    s_label  = ps('lbl', fontName='Helvetica-Bold', fontSize=9, textColor=TEXT_GREY)
    s_value  = ps('val', fontName='Helvetica', fontSize=10, textColor=TEXT_DARK)
    s_footer = ps('ftr', fontName='Helvetica', fontSize=7.5, textColor=TEXT_GREY,
                  alignment=TA_CENTER)
    s_valid  = ps('vld', fontName='Helvetica-Bold', fontSize=11, textColor=GREEN,
                  alignment=TA_CENTER)
    s_sig_l  = ps('sigl', fontName='Helvetica-Bold', fontSize=9, textColor=GOV_DARK,
                  alignment=TA_CENTER)
    s_sig_s  = ps('sigs', fontName='Helvetica', fontSize=8, textColor=TEXT_GREY,
                  alignment=TA_CENTER)

    page_w = A4[0] - 3.6*cm   # usable width

    # ── HEADER BANNER ─────────────────────────────────────────────────────────
    seal = _seal_drawing()

    header_left = [
        [Paragraph('PKI-Based Secure Government Digital Service System', s_system)],
        [Paragraph('GOVERNMENT OF NEPAL', s_govt)],
        [Paragraph('Department of Digital Government Services', s_dept)],
        [Paragraph('Singha Durbar, Kathmandu, Nepal', s_dept)],
    ]
    header_tbl = Table(
        [[seal, Table(header_left, colWidths=[page_w - 2.8*cm],
                      style=TableStyle([('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                                         ('TOPPADDING', (0,0), (-1,-1), 3)]))]],
        colWidths=[2.8*cm, page_w - 2.8*cm],
    )
    header_tbl.setStyle(TableStyle([
        ('BACKGROUND',  (0,0), (-1,-1), GOV_DARK),
        ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING',(0,0), (-1,-1), 10),
        ('TOPPADDING',  (0,0), (-1,-1), 12),
        ('BOTTOMPADDING',(0,0),(-1,-1), 12),
        ('ROUNDEDCORNERS', (0,0), (-1,-1), [6,6,0,0]),
    ]))
    story.append(header_tbl)

    # Gold top border under header
    story.append(HRFlowable(width='100%', thickness=3, color=GOLD, spaceAfter=0, spaceBefore=0))

    # ── CERTIFICATE TITLE BAND ────────────────────────────────────────────────
    title_tbl = Table(
        [[Paragraph('OFFICIAL APPROVAL CERTIFICATE', s_cert_h)],
         [Paragraph('Issued under the authority of the Government of Nepal', s_cert_s)]],
        colWidths=[page_w],
    )
    title_tbl.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,-1), GOV_BG),
        ('TOPPADDING',   (0,0), (-1,-1), 10),
        ('BOTTOMPADDING',(0,0), (-1,-1), 8),
    ]))
    story.append(title_tbl)
    story.append(HRFlowable(width='100%', thickness=1.5, color=GOV_MID, spaceAfter=14, spaceBefore=0))

    # ── CERTIFICATE DETAILS TABLE ─────────────────────────────────────────────
    def row(label, value):
        return [Paragraph(label, s_label), Paragraph(str(value), s_value)]

    rows = [
        row('Certificate Number', cert_number),
        row('Application / Tracking Number', appl['tracking_number']),
        row('Service Type', service_label),
        row('Applicant Full Name', citizen['full_name']),
    ]
    if citizenship_number:
        rows.append(row('Citizenship Number', citizenship_number))
    rows += [
        row('Approval Date', approval_date),
        row('Approved By (Officer)', officer['full_name']),
    ]
    if appl.get('admin_notes'):
        rows.append(row('Officer Remarks', appl['admin_notes']))

    det_tbl = Table(rows, colWidths=[5.5*cm, page_w - 5.5*cm])
    det_tbl.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (0,-1), colors.HexColor('#f7f9fc')),
        ('GRID',         (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING',   (0,0), (-1,-1), 7),
        ('BOTTOMPADDING',(0,0), (-1,-1), 7),
        ('LEFTPADDING',  (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS',(0,0),(-1,-1), [WHITE, colors.HexColor('#f7f9fc')]),
        ('FONTNAME',     (0,0), (0,-1),  'Helvetica-Bold'),
    ]))
    story.append(det_tbl)
    story.append(Spacer(1, 16))

    # ── APPROVAL STATEMENT ────────────────────────────────────────────────────
    stmt_box = Table(
        [[Paragraph(
            f'This is to officially certify that the application submitted by '
            f'<b>{citizen["full_name"]}</b> for <b>{service_label}</b> '
            f'has been reviewed, verified, and <b>APPROVED</b> by the Government of Nepal '
            f'Digital Services System. This certificate is issued as proof of approval '
            f'and is digitally authenticated using Public Key Infrastructure (PKI).',
            s_body
        )]],
        colWidths=[page_w],
    )
    stmt_box.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,-1), GOLD_LIGHT),
        ('BOX',          (0,0), (-1,-1), 1, GOLD),
        ('TOPPADDING',   (0,0), (-1,-1), 12),
        ('BOTTOMPADDING',(0,0), (-1,-1), 12),
        ('LEFTPADDING',  (0,0), (-1,-1), 14),
        ('RIGHTPADDING', (0,0), (-1,-1), 14),
        ('ROUNDEDCORNERS',(0,0),(-1,-1), [4,4,4,4]),
    ]))
    story.append(stmt_box)
    story.append(Spacer(1, 12))

    # ── VALID STAMP LINE ──────────────────────────────────────────────────────
    story.append(Paragraph('✔  APPLICATION STATUS: APPROVED', s_valid))
    story.append(Spacer(1, 18))

    # ── SIGNATURE + QR SECTION ───────────────────────────────────────────────
    qr_content = (f"Certificate: {cert_number} | Application: {appl['tracking_number']} | "
                  f"Applicant: {citizen['full_name']} | Service: {service_label} | "
                  f"Approved: {approval_date} | Issued: {issued_time}")
    qr_img = _generate_qr(qr_content)

    sig_lines_officer = [
        [Paragraph('___________________________', s_sig_l)],
        [Paragraph(officer['full_name'], s_sig_l)],
        [Paragraph('Government Officer', s_sig_s)],
        [Paragraph('Dept. of Digital Government Services', s_sig_s)],
        [Paragraph('Government of Nepal', s_sig_s)],
    ]
    sig_lines_auth = [
        [Paragraph('___________________________', s_sig_l)],
        [Paragraph('System Administrator', s_sig_l)],
        [Paragraph('PKI Certificate Authority', s_sig_s)],
        [Paragraph('Nepal Gov Root CA', s_sig_s)],
        [Paragraph('Government of Nepal', s_sig_s)],
    ]

    sig_officer_tbl = Table(sig_lines_officer, colWidths=[(page_w-3*cm)/2])
    sig_officer_tbl.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER'),
                                          ('TOPPADDING',(0,0),(-1,-1),3)]))
    sig_auth_tbl = Table(sig_lines_auth, colWidths=[(page_w-3*cm)/2])
    sig_auth_tbl.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER'),
                                       ('TOPPADDING',(0,0),(-1,-1),3)]))

    qr_wrapper = Table(
        [[qr_img],
         [Paragraph('Scan to Verify', s_sig_s)],
         [Paragraph('Authenticity QR', s_sig_s)]],
        colWidths=[3*cm],
    )
    qr_wrapper.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER'),
                                     ('TOPPADDING',(0,0),(-1,-1),2)]))

    sig_row = Table(
        [[sig_officer_tbl, sig_auth_tbl, qr_wrapper]],
        colWidths=[(page_w-3*cm)/2, (page_w-3*cm)/2, 3*cm],
    )
    sig_row.setStyle(TableStyle([
        ('VALIGN',(0,0),(-1,-1),'BOTTOM'),
        ('TOPPADDING',(0,0),(-1,-1),0),
        ('LEFTPADDING',(0,0),(-1,-1),4),
        ('RIGHTPADDING',(0,0),(-1,-1),4),
    ]))
    story.append(sig_row)
    story.append(Spacer(1, 18))

    # ── FOOTER ────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width='100%', thickness=1, color=GOV_MID, spaceAfter=6))
    footer_data = [[
        Paragraph(f'Certificate No: {cert_number}', s_footer),
        Paragraph(f'Generated: {issued_time}', s_footer),
        Paragraph('Nepal Digital Government Services', s_footer),
    ]]
    footer_tbl = Table(footer_data, colWidths=[page_w/3]*3)
    footer_tbl.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1), GOV_BG),
        ('TOPPADDING',(0,0),(-1,-1),6),
        ('BOTTOMPADDING',(0,0),(-1,-1),6),
        ('LEFTPADDING',(0,0),(-1,-1),6),
    ]))
    story.append(footer_tbl)

    doc.build(story)
    return cert_number, pdf_filename
