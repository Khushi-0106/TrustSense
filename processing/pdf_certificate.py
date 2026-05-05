from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, Flowable
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from datetime import datetime
import os
import qrcode
import platform

class LineFlowable(Flowable):
    def __init__(self, width, color=colors.HexColor("#00f3ff")):
        Flowable.__init__(self)
        self.width = width
        self.color = color

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(2)
        self.canv.line(0, 0, self.width, 0)

def generate_pdf_certificate(data):
    try:
        file_name = os.path.join(os.getcwd(), f"{data['device_id']}_certificate.pdf")

        # Premium Dark Margins
        doc = SimpleDocTemplate(file_name, pagesize=A4,
                                rightMargin=40, leftMargin=40,
                                topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()

        # Custom Styles
        title_style = ParagraphStyle(
            name='PremiumTitle',
            fontName='Helvetica-Bold',
            fontSize=24,
            textColor=colors.HexColor("#0f172a"), # Dark Slate
            alignment=1,
            spaceAfter=10
        )
        subtitle_style = ParagraphStyle(
            name='PremiumSubtitle',
            fontName='Helvetica',
            fontSize=12,
            textColor=colors.HexColor("#64748b"), # Slate Gray
            alignment=1,
            spaceAfter=30
        )
        header_style = ParagraphStyle(
            name='SectionHeader',
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=colors.HexColor("#06b6d4"), # Cyan accent
            spaceAfter=10,
            spaceBefore=20
        )
        
        device_name = platform.node()
        content = []

        # Header section
        content.append(Paragraph("TRUSTSENSE+ SECURITY PASSPORT", title_style))
        content.append(Paragraph("OFFICIAL DEVICE SANITIZATION RECORD", subtitle_style))
        content.append(LineFlowable(doc.width, colors.HexColor("#06b6d4")))
        content.append(Spacer(1, 20))

        # Device Info Section
        content.append(Paragraph("DEVICE IDENTITY", header_style))
        info_data = [
            ["Device ID:", data["device_id"], "Device Name:", device_name],
            ["Certified On:", datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), "Score:", f"{data['trust_score']}/100"]
        ]
        info_table = Table(info_data, colWidths=[1.2*inch, 2*inch, 1.2*inch, 2*inch])
        info_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor("#334155")),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        content.append(info_table)
        content.append(Spacer(1, 20))

        # Wipe Details Section
        content.append(Paragraph("SANITIZATION PROTOCOL", header_style))
        wipe_data = [
            ["Protocol Used", data["wipe_method"]],
            ["Files Wiped", str(data["files_wiped"])],
            ["Folders Wiped", str(data.get("folders_wiped", 0))],
            ["Risk Detected", data["risk_level"]],
        ]
        wipe_table = Table(wipe_data, colWidths=[2.5*inch, 3.9*inch])
        wipe_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor("#0f172a")),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
            ('LINEBELOW', (0,0), (-1,-2), 1, colors.HexColor("#e2e8f0")),
            ('PADDING', (0,0), (-1,-1), 10),
        ]))
        content.append(wipe_table)
        content.append(Spacer(1, 20))

        # Final Status
        status_color = colors.HexColor("#10b981") if data["status"] == "SAFE" else colors.HexColor("#ef4444")
        status_text = f"<font color='{status_color}'>{data['status']} FOR RESALE</font>"
        content.append(Paragraph("FINAL VERDICT", header_style))
        
        status_data = [
            ["Status:", Paragraph(status_text, styles['Normal'])],
            ["SHA-256 Hash:", data["hash"][:40] + "..."]
        ]
        status_table = Table(status_data, colWidths=[1.5*inch, 4.9*inch])
        status_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        content.append(status_table)
        content.append(Spacer(1, 30))

        # QR Code Verification
        qr_data = f"ID:{data['device_id']}|SCORE:{data['trust_score']}|STATUS:{data['status']}|HASH:{data['hash']}"
        
        qr_obj = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr_obj.add_data(qr_data)
        qr_obj.make(fit=True)
        qr_img = qr_obj.make_image(fill_color="black", back_color="white")
        
        qr_path = os.path.join(os.getcwd(), "qr_code.png")
        qr_img.save(qr_path)
        
        content.append(LineFlowable(doc.width, colors.HexColor("#e2e8f0")))
        content.append(Spacer(1, 15))
        
        qr_table = Table([[
            Image(qr_path, width=1.5*inch, height=1.5*inch),
            Paragraph("<b>VERIFICATION QR</b><br/>Scan to verify the authenticity of this digital certificate.<br/><br/><i>Generated by TrustSense+ Platform</i>", styles['Normal'])
        ]], colWidths=[1.8*inch, 4.6*inch])
        qr_table.setStyle(TableStyle([('VALIGN', (0,0), (-1,-1), 'MIDDLE')]))
        
        content.append(qr_table)

        doc.build(content)
        return file_name

    except Exception as e:
        print("PDF Error:", e)
        return None