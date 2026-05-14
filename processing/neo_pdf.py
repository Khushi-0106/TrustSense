import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, Flowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.barcode import code128
from datetime import datetime
import qrcode
from io import BytesIO
import socket

def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"

def generate_neo_pdf(data):
    """
    Generates a premium Cyber-Brutalist PDF Security Passport using reportlab.
    """
    device_id = data.get('device_id', 'TS-UNIT-01')
    sha_hash = data.get('hash', 'UNKNOWN_HASH')
    trust_score = data.get('trust_score', 100)
    date = data.get('date', datetime.now().strftime("%Y-%m-%d"))
    files_sensitive = data.get('files_sensitive', 0)
    files_safe = data.get('files_safe', 0)

    # TrustSense Elite Color Palette
    bg_dark = colors.HexColor("#050B14")
    trust_green = colors.HexColor("#10B981")
    trust_cyan = colors.HexColor("#06B6D4")
    trust_yellow = colors.HexColor("#FBBF24")
    text_white = colors.HexColor("#FFFFFF")
    text_gray = colors.HexColor("#9CA3AF")

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    # Custom Styles
    style_title = ParagraphStyle('NeoTitle', fontName='Helvetica-Bold', fontSize=28, textColor=bg_dark, alignment=1)
    style_subtitle = ParagraphStyle('NeoSub', fontName='Courier-Bold', fontSize=10, textColor=bg_dark, alignment=1, leading=14)
    
    style_label = ParagraphStyle('NeoLabel', fontName='Courier-Bold', fontSize=9, textColor=text_gray, leading=14)
    style_value = ParagraphStyle('NeoValue', fontName='Helvetica-Bold', fontSize=24, textColor=text_white, leading=28)
    
    style_mono_green = ParagraphStyle('NeoMonoG', fontName='Courier-Bold', fontSize=11, textColor=trust_green, leading=14)
    style_mono_yellow = ParagraphStyle('NeoMonoY', fontName='Courier-Bold', fontSize=10, textColor=trust_yellow, leading=14, alignment=1)

    elements = []

    # 1. Header Block (Solid Green)
    header_data = [
        [Paragraph("OFFICIAL SECURITY PASSPORT", style_title)],
        [Paragraph("CRYPTOGRAPHIC ERADICATION CERTIFICATE [ ZERO-BIT SECURE ]", style_subtitle)]
    ]
    header_table = Table(header_data, colWidths=[doc.width])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), trust_green),
        ('BOX', (0, 0), (-1, -1), 3, text_white),
        ('TOPPADDING', (0, 0), (-1, -1), 20),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 20))

    # 2. Barcode & ID Strip
    barcode = code128.Code128(sha_hash[:12], barHeight=0.4*inch, barWidth=1.2)
    
    id_data = [
        [barcode, Paragraph(f"CERT ID: {sha_hash[:12]}<br/>NODE: {device_id}", style_mono_yellow)]
    ]
    id_table = Table(id_data, colWidths=[doc.width/2, doc.width/2])
    id_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOX', (0, 0), (-1, -1), 1, text_gray),
        ('PADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(id_table)
    elements.append(Spacer(1, 30))

    # 3. Core Metrics Grid
    def metric_box(label, value, color):
        return Table(
            [[Paragraph(label, style_label)], [Paragraph(str(value), ParagraphStyle('V', fontName='Helvetica-Bold', fontSize=32, textColor=color))]],
            colWidths=[doc.width/2.1]
        )

    metrics_data = [
        [metric_box("THREATS PURGED", files_sensitive, trust_green), metric_box("TOTAL VALIDATED", files_safe, trust_cyan)]
    ]
    metrics_table = Table(metrics_data, colWidths=[doc.width/2, doc.width/2])
    metrics_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 30))

    # 4. Eradication Protocol Data
    protocol_data = [
        [Paragraph("PROTOCOL DEPLOYED", style_label), Paragraph("ANTIGRAVITY v4.2", style_mono_green)],
        [Paragraph("VERIFIED INTEGRITY", style_label), Paragraph(f"{trust_score}% SECURE", style_value)],
        [Paragraph("TIMESTAMP", style_label), Paragraph(date, style_mono_green)]
    ]
    protocol_table = Table(protocol_data, colWidths=[doc.width*0.4, doc.width*0.6])
    protocol_table.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -2), 1, colors.Color(1, 1, 1, alpha=0.1)),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(protocol_table)
    elements.append(Spacer(1, 40))

    # 5. QR Code and Signature Block
    local_ip = get_local_ip()
    verify_url = f"http://{local_ip}:8501/?verify=true&id={device_id}&hash={sha_hash}"
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="#10B981", back_color="#050B14") # Trust green on dark bg
    
    qr_buffer = BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    qr_reportlab = Image(qr_buffer, width=1.5*inch, height=1.5*inch)
    
    sig_data = [
        [qr_reportlab, Paragraph("<i>TrustSense Cryptographic Engine</i><br/><br/>_______________________________<br/>AUTHORIZED SIGNATURE", ParagraphStyle('Sig', fontName='Times-Italic', fontSize=14, textColor=text_gray, alignment=1))]
    ]
    sig_table = Table(sig_data, colWidths=[doc.width*0.3, doc.width*0.7])
    sig_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
    ]))
    elements.append(sig_table)
    elements.append(Spacer(1, 30))

    # 6. Bottom Hash Ribbon
    hash_data = [[Paragraph(f"SHA-256 SIGNATURE: {sha_hash}", ParagraphStyle('H', fontName='Courier-Bold', fontSize=8, textColor=bg_dark, alignment=1))]]
    hash_table = Table(hash_data, colWidths=[doc.width])
    hash_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), trust_yellow),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(hash_table)

    # Page Background
    def add_background(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(bg_dark)
        canvas.rect(0, 0, A4[0], A4[1], fill=1)
        
        # Cyber grid watermark (very faint)
        canvas.setStrokeColor(colors.Color(0.023, 0.713, 0.831, alpha=0.05)) # Cyan
        canvas.setLineWidth(0.5)
        for i in range(0, int(A4[0]), 20):
            canvas.line(i, 0, i, A4[1])
        for i in range(0, int(A4[1]), 20):
            canvas.line(0, i, A4[0], i)
            
        # Outer Border
        canvas.setStrokeColor(trust_green)
        canvas.setLineWidth(4)
        canvas.rect(15, 15, A4[0]-30, A4[1]-30)
        canvas.restoreState()

    doc.build(elements, onFirstPage=add_background, onLaterPages=add_background)
    return buffer.getvalue()

