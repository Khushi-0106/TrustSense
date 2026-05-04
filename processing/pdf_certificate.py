from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from datetime import datetime
import os
import qrcode

def generate_pdf_certificate(data):
    try:
        file_name = os.path.join(os.getcwd(), f"{data['device_id']}_certificate.pdf")

        doc = SimpleDocTemplate(file_name, pagesize=A4)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            name='TitleStyle',
            fontSize=18,
            textColor=colors.green,
            alignment=1,
            spaceAfter=20
        )

        content = []

        # TITLE
        content.append(Paragraph("TRUSTSENSE+ DIGITAL CERTIFICATE", title_style))
        content.append(Spacer(1, 10))

        # TABLE DATA
        table_data = [
            ["Device ID", data["device_id"]],
            ["Trust Score", f"{data['trust_score']}/100"],
            ["Risk Level", data["risk_level"]],
            ["Wipe Method", data["wipe_method"]],
            ["Files Wiped", str(data["files_wiped"])],
            ["Verification Hash", data["hash"][:25] + "..."],
            ["Final Status", data["status"]],
        ]

        table = Table(table_data, colWidths=[2.5 * inch, 4 * inch])

        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.darkgreen),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.green),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))

        content.append(table)
        content.append(Spacer(1, 20))

        # QR DATA
        qr_data = f"""
Device ID: {data['device_id']}
Trust Score: {data['trust_score']}
Status: {data['status']}
Hash: {data['hash']}
"""

        qr = qrcode.make(qr_data)

        qr_path = os.path.join(os.getcwd(), "qr_code.png")
        qr.save(qr_path)

        content.append(Paragraph("Scan for Verification", styles["Normal"]))
        content.append(Spacer(1, 10))
        content.append(Image(qr_path, width=2*inch, height=2*inch))

        content.append(Spacer(1, 20))

        content.append(Paragraph(
            f"Certified At: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            styles["Normal"]
        ))

        doc.build(content)

        return file_name

    except Exception as e:
        print("PDF Error:", e)
        return None