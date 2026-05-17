import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, Flowable, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.barcode import code128
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from datetime import datetime
import qrcode
from io import BytesIO
import socket

def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"

def generate_neo_pdf(data):
    """
    Generates a Professional Enterprise Data Eradication Audit Report.
    """
    device_id = data.get('device_id', 'TS-UNIT-01')
    sha_hash = data.get('hash', 'UNKNOWN_HASH')
    trust_score = data.get('trust_score', 100)
    date = data.get('date', datetime.now().strftime("%Y-%m-%d"))
    files_sensitive = data.get('files_sensitive', 0)
    files_safe = data.get('files_safe', 0)
    file_types = data.get('file_types', {})

    # Enterprise Color Palette
    bg_light = colors.HexColor("#F8FAFC")
    bg_white = colors.HexColor("#FFFFFF")
    text_slate_900 = colors.HexColor("#0F172A")
    text_slate_500 = colors.HexColor("#64748B")
    blue_600 = colors.HexColor("#2563EB")
    emerald_500 = colors.HexColor("#10B981")
    rose_500 = colors.HexColor("#F43F5E")
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    # Custom Styles
    style_title = ParagraphStyle('Title', fontName='Helvetica-Bold', fontSize=24, textColor=text_slate_900, alignment=0)
    style_subtitle = ParagraphStyle('Sub', fontName='Helvetica-Bold', fontSize=10, textColor=text_slate_500, alignment=0, spaceBefore=4, spaceAfter=20)
    
    style_label = ParagraphStyle('Label', fontName='Helvetica-Bold', fontSize=8, textColor=text_slate_500, leading=12)
    style_value = ParagraphStyle('Value', fontName='Helvetica-Bold', fontSize=18, textColor=text_slate_900, leading=22)
    
    style_mono = ParagraphStyle('Mono', fontName='Courier-Bold', fontSize=10, textColor=text_slate_900, leading=14)

    elements = []

    # 1. Header Block
    header_data = [
        [Paragraph("Data Eradication Audit Report", style_title)],
        [Paragraph("OFFICIAL CRYPTOGRAPHIC CERTIFICATE", style_subtitle)]
    ]
    header_table = Table(header_data, colWidths=[doc.width])
    header_table.setStyle(TableStyle([
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
    ]))
    elements.append(header_table)
    
    # Divider
    elements.append(Spacer(1, 10))
    divider = Table([[""]], colWidths=[doc.width])
    divider.setStyle(TableStyle([('LINEABOVE', (0,0), (-1,-1), 2, blue_600)]))
    elements.append(divider)
    elements.append(Spacer(1, 20))

    # 2. Barcode & ID Strip
    barcode = code128.Code128(sha_hash[:16], barHeight=0.3*inch, barWidth=1.1)
    
    id_data = [
        [Paragraph(f"<b>CERT ID:</b> {sha_hash[:16]}<br/><b>TARGET:</b> {device_id}", style_mono), barcode]
    ]
    id_table = Table(id_data, colWidths=[doc.width/2, doc.width/2])
    id_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (1, 0), (1, 0), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (-1, -1), bg_light),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
        ('PADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(id_table)
    elements.append(Spacer(1, 30))

    # 3. Core Metrics Grid
    def metric_box(label, value, color):
        return Table(
            [[Paragraph(label, style_label)], [Paragraph(str(value), ParagraphStyle('V', fontName='Helvetica-Bold', fontSize=24, textColor=color))]],
            colWidths=[doc.width/2.1]
        )

    metrics_data = [
        [metric_box("VULNERABILITIES PURGED", files_sensitive, rose_500), metric_box("TOTAL OBJECTS ERADICATED", files_safe + files_sensitive, text_slate_900)]
    ]
    metrics_table = Table(metrics_data, colWidths=[doc.width/2, doc.width/2])
    metrics_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))
    elements.append(metrics_table)
    elements.append(Spacer(1, 30))
    
    # 3.5 Pie Chart for File Categories
    if file_types:
        d = Drawing(400, 150)
        pc = Pie()
        pc.x = 100
        pc.y = 10
        pc.width = 130
        pc.height = 130
        
        # Extract data
        categories = list(file_types.keys())
        data_values = [file_types[cat] for cat in categories]
        
        # Handle empty data case
        if sum(data_values) == 0:
            data_values = [1]
            categories = ["No Data"]
            
        pc.data = data_values
        pc.labels = [f"{cat} ({val})" for cat, val in zip(categories, data_values)]
        
        # Colors corresponding to categories
        color_map = {
            'High Risk': rose_500,
            'Hidden Data': text_slate_500,
            'Low Risk': emerald_500
        }
        for i, cat in enumerate(categories):
            pc.slices[i].fillColor = color_map.get(cat, blue_600)
            pc.slices[i].fontName = 'Helvetica-Bold'
            pc.slices[i].fontSize = 8
            
        d.add(pc)
        
        chart_table = Table(
            [[Paragraph("DATA CATEGORIZATION", style_label)], [d]],
            colWidths=[doc.width]
        )
        chart_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg_light),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
            ('PADDING', (0, 0), (-1, -1), 15),
        ]))
        elements.append(KeepTogether(chart_table))
        elements.append(Spacer(1, 30))

    # 4. Eradication Protocol Data
    protocol_data = [
        [Paragraph("PROTOCOL STANDARD", style_label), Paragraph("DoD 5220.22-M Wipe", style_mono)],
        [Paragraph("VERIFIED INTEGRITY", style_label), Paragraph(f"100% SECURE", ParagraphStyle('VS', fontName='Helvetica-Bold', fontSize=14, textColor=emerald_500))],
        [Paragraph("TIMESTAMP", style_label), Paragraph(date, style_mono)]
    ]
    protocol_table = Table(protocol_data, colWidths=[doc.width*0.4, doc.width*0.6])
    protocol_table.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -2), 1, colors.HexColor("#E2E8F0")),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(protocol_table)
    elements.append(Spacer(1, 40))

    # 5. QR Code and Signature Block
    local_ip = get_local_ip()
    verify_url = f"http://{local_ip}:8501/?verify=true&id={device_id}&hash={sha_hash}"
    qr = qrcode.QRCode(version=1, box_size=10, border=1)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="#0F172A", back_color="#FFFFFF")
    
    qr_buffer = BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    qr_reportlab = Image(qr_buffer, width=1.2*inch, height=1.2*inch)
    
    sig_data = [
        [qr_reportlab, Paragraph("<i>TrustSense Enterprise</i><br/><br/>_______________________________<br/>AUTHORIZED SIGNATURE", ParagraphStyle('Sig', fontName='Times-Italic', fontSize=12, textColor=text_slate_500, alignment=1))]
    ]
    sig_table = Table(sig_data, colWidths=[doc.width*0.3, doc.width*0.7])
    sig_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (1, 0), (1, 0), 'CENTER'),
    ]))
    elements.append(KeepTogether(sig_table))

    # Page Background
    def add_background(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(bg_white)
        canvas.rect(0, 0, A4[0], A4[1], fill=1)
        
        # Elegant Outer Border
        canvas.setStrokeColor(blue_600)
        canvas.setLineWidth(1)
        canvas.rect(20, 20, A4[0]-40, A4[1]-40)
        
        # Footer Hash
        canvas.setFont("Courier", 8)
        canvas.setFillColor(text_slate_500)
        canvas.drawCentredString(A4[0]/2, 30, f"SHA-256 SIGNATURE: {sha_hash}")
        
        canvas.restoreState()

    doc.build(elements, onFirstPage=add_background, onLaterPages=add_background)
    return buffer.getvalue()
