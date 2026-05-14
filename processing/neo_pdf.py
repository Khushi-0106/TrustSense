import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, Flowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import qrcode
from io import BytesIO
import socket

def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"

class BoxFlowable(Flowable):
    def __init__(self, width, height, bg_color, border_color, border_width=2):
        Flowable.__init__(self)
        self.width = width
        self.height = height
        self.bg_color = bg_color
        self.border_color = border_color
        self.border_width = border_width

    def draw(self):
        self.canv.setStrokeColor(self.border_color)
        self.canv.setFillColor(self.bg_color)
        self.canv.setLineWidth(self.border_width)
        self.canv.rect(0, 0, self.width, self.height, fill=1)

class DashedBoxFlowable(Flowable):
    def __init__(self, width, height, border_color):
        Flowable.__init__(self)
        self.width = width
        self.height = height
        self.border_color = border_color

    def draw(self):
        self.canv.setStrokeColor(self.border_color)
        self.canv.setLineWidth(2)
        self.canv.setDash(4, 4)
        self.canv.rect(0, 0, self.width, self.height)

def generate_neo_pdf(data):
    """
    Generates a high-fidelity Pastel Neo-Brutalist PDF Security Passport using reportlab.
    Replaces the xhtml2pdf implementation for better compatibility.
    """
    device_id = data.get('device_id', 'TS-UNIT-01')
    sha_hash = data.get('hash', 'UNKNOWN_HASH')
    trust_score = data.get('trust_score', 100)
    date = data.get('date', datetime.now().strftime("%Y-%m-%d"))
    files_sensitive = data.get('files_sensitive', 0)
    files_safe = data.get('files_safe', 0)

    # Colors
    bg_dark = colors.HexColor("#1A1A1A")
    pastel_green = colors.HexColor("#B2F2BB")
    pastel_yellow = colors.HexColor("#FFF3BF")
    data_bg = colors.HexColor("#2D2D2D")
    text_gray = colors.HexColor("#E0E0E0")
    label_gray = colors.HexColor("#B0B0B0")

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    styles = getSampleStyleSheet()

    # Custom Styles
    style_header = ParagraphStyle(
        'NeoHeader',
        fontName='Helvetica-Bold',
        fontSize=26,
        textColor=colors.black,
        alignment=1,
    )
    style_label = ParagraphStyle(
        'NeoLabel',
        fontName='Helvetica',
        fontSize=10,
        textColor=label_gray,
        leading=12,
    )
    style_value = ParagraphStyle(
        'NeoValue',
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=pastel_green,
        leading=24,
    )
    style_id = ParagraphStyle(
        'NeoID',
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.black,
        alignment=1,
    )
    style_score = ParagraphStyle(
        'NeoScore',
        fontName='Helvetica-Bold',
        fontSize=36,
        textColor=pastel_green,
        alignment=2,
    )
    style_hash = ParagraphStyle(
        'NeoHash',
        fontName='Courier',
        fontSize=9,
        textColor=colors.black,
        leading=11,
    )

    elements = []

    # 1. Score Badge (Top Right)
    elements.append(Paragraph(f"{trust_score}/100", style_score))
    elements.append(Spacer(1, 10))

    # 2. Main Header Strip
    header_data = [[Paragraph("SECURITY PASSPORT", style_header)]]
    header_table = Table(header_data, colWidths=[doc.width])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), pastel_green),
        ('BOX', (0, 0), (-1, -1), 4, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 25))

    # 3. Identity Bar
    id_data = [[Paragraph(f"ID: {device_id} | DATE: {date}", style_id)]]
    id_table = Table(id_data, colWidths=[doc.width])
    id_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), pastel_yellow),
        ('BOX', (0, 0), (-1, -1), 4, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(id_table)
    elements.append(Spacer(1, 25))

    # 4. Data Boxes
    def create_data_box(label, value):
        box_content = [
            [Paragraph(label, style_label)],
            [Paragraph(value, style_value)]
        ]
        t = Table(box_content, colWidths=[doc.width - 20])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), data_bg),
            ('BOX', (0, 0), (-1, -1), 4, text_gray),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
        ]))
        return t

    elements.append(create_data_box("SENSITIVE DATA DETECTED:", f"{files_sensitive} OBJECTS"))
    elements.append(Spacer(1, 15))
    elements.append(create_data_box("SECURE DATA REMAINING:", f"{files_safe} OBJECTS"))
    elements.append(Spacer(1, 25))

    # 5. Protocol Section
    protocol_text = [
        [Paragraph("SANITIZATION PROTOCOL", style_label)],
        [Paragraph("[ ANTIGRAVITY v4.0 ]", ParagraphStyle('NeoProtocol', fontName='Helvetica-Bold', fontSize=14, textColor=pastel_green, alignment=1))],
        [Paragraph("MULTI-PASS CRYPTOGRAPHIC ERASE", ParagraphStyle('NeoProtocolSub', fontName='Helvetica', fontSize=10, textColor=text_gray, alignment=1))]
    ]
    protocol_table = Table(protocol_text, colWidths=[doc.width])
    protocol_table.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 2, pastel_green),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        # Reportlab doesn't easily support dashed borders on tables via TableStyle, 
        # so we'll just use a solid line for now or a custom flowable if needed.
    ]))
    # For dashed look, we can wrap it or draw it. Simple solid is safer for now.
    elements.append(protocol_table)
    elements.append(Spacer(1, 25))

    # 6. QR Code
    local_ip = get_local_ip()
    verify_url = f"http://{local_ip}:8501/?verify=true&id={device_id}&hash={sha_hash}"
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(verify_url)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    qr_buffer = BytesIO()
    qr_img.save(qr_buffer, format="PNG")
    qr_buffer.seek(0)
    
    qr_reportlab = Image(qr_buffer, width=1.3*inch, height=1.3*inch)
    
    qr_section = [
        [qr_reportlab],
        [Paragraph("AUTHENTICITY VERIFIED", ParagraphStyle('NeoAuth', fontName='Helvetica-Bold', fontSize=10, textColor=text_gray, alignment=1))]
    ]
    qr_table = Table(qr_section, colWidths=[doc.width])
    qr_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(qr_table)
    elements.append(Spacer(1, 20))

    # 7. Footer Hash
    hash_data = [[Paragraph(f"SHA-256 HASH:<br/>{sha_hash}", style_hash)]]
    hash_table = Table(hash_data, colWidths=[doc.width])
    hash_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), pastel_yellow),
        ('BOX', (0, 0), (-1, -1), 4, colors.black),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
    ]))
    elements.append(hash_table)

    # Background Drawing
    def add_background(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(bg_dark)
        canvas.rect(0, 0, A4[0], A4[1], fill=1)
        # Main Border
        canvas.setStrokeColor(pastel_green)
        canvas.setLineWidth(6)
        canvas.rect(20, 20, A4[0]-40, A4[1]-40)
        canvas.restoreState()

    doc.build(elements, onFirstPage=add_background, onLaterPages=add_background)
    
    return buffer.getvalue()

