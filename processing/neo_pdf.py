import base64
import qrcode
from io import BytesIO
from xhtml2pdf import pisa
from datetime import datetime
from ui_components import get_local_ip

def generate_neo_pdf(data):
    """
    Generates a high-fidelity Pastel Neo-Brutalist PDF Security Passport using xhtml2pdf.
    """
    device_id = data.get('device_id', 'TS-UNIT-01')
    sha_hash = data.get('hash', 'UNKNOWN_HASH')
    trust_score = data.get('trust_score', 100)
    date = data.get('date', datetime.now().strftime("%Y-%m-%d"))
    files_sensitive = data.get('files_sensitive', 0)
    files_safe = data.get('files_safe', 0)

    # 1. QR Logic: Generate QR with verification URL
    local_ip = get_local_ip()
    verify_url = f"http://{local_ip}:8501/?verify=true&id={device_id}&hash={sha_hash}"
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(verify_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    # 2. HTML Template (Pastel Neo-Brutalist Design)
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            @page {{
                size: A4;
                margin: 0.5in;
            }}
            body {{
                background-color: #1A1A1A;
                color: #E0E0E0;
                font-family: Helvetica, sans-serif;
                margin: 0;
                padding: 0;
            }}
            .main-border {{
                border: 6px solid #B2F2BB;
                padding: 30px;
                background-color: #1A1A1A;
            }}
            .header-strip {{
                background-color: #B2F2BB;
                color: #000000;
                padding: 20px;
                border: 4px solid #000000;
                text-align: center;
                margin-bottom: 25px;
            }}
            .header-strip h1 {{
                font-size: 26pt;
                margin: 0;
                font-weight: bold;
                text-transform: uppercase;
            }}
            .score-badge {{
                text-align: right;
                font-size: 36pt;
                color: #B2F2BB;
                font-weight: bold;
                margin-bottom: 10px;
            }}
            .identity-bar {{
                background-color: #FFF3BF;
                color: #000000;
                padding: 12px;
                border: 4px solid #000000;
                font-weight: bold;
                margin-bottom: 25px;
                text-align: center;
                font-size: 14pt;
            }}
            .data-box {{
                border: 4px solid #E0E0E0;
                padding: 15px;
                margin-bottom: 15px;
                background-color: #2D2D2D;
            }}
            .label {{
                font-size: 10pt;
                color: #B0B0B0;
                text-transform: uppercase;
            }}
            .value {{
                font-size: 20pt;
                color: #B2F2BB;
                font-weight: bold;
            }}
            .protocol-section {{
                border: 4px dashed #B2F2BB;
                padding: 20px;
                margin-bottom: 30px;
                text-align: center;
            }}
            .qr-container {{
                text-align: center;
                margin-bottom: 20px;
            }}
            .qr-image {{
                border: 3px solid #E0E0E0;
                width: 130px;
                height: 130px;
            }}
            .footer-hash {{
                background-color: #FFF3BF;
                color: #000000;
                padding: 12px;
                font-size: 9pt;
                font-family: Courier, monospace;
                border: 4px solid #000000;
                word-wrap: break-word;
            }}
            .caution-line {{
                height: 12px;
                background-color: #FFF3BF;
                border-top: 2px solid #000000;
                border-bottom: 2px solid #000000;
                margin-bottom: 10px;
            }}
        </style>
    </head>
    <body>
        <div class="main-border">
            <div class="score-badge">
                {trust_score}/100
            </div>

            <div class="header-strip">
                <h1>SECURITY PASSPORT</h1>
            </div>

            <div class="caution-line"></div>
            
            <div class="identity-bar">
                ID: {device_id} | DATE: {date}
            </div>

            <div class="data-box">
                <span class="label">SENSITIVE DATA DETECTED:</span><br/>
                <span class="value">{files_sensitive} OBJECTS</span>
            </div>

            <div class="data-box">
                <span class="label">SECURE DATA REMAINING:</span><br/>
                <span class="value">{files_safe} OBJECTS</span>
            </div>

            <div class="protocol-section">
                <span class="label">SANITIZATION PROTOCOL</span><br/>
                <span style="font-size: 14pt; color: #B2F2BB; font-weight: bold;">[ ANTIGRAVITY v4.0 ]</span><br/>
                <span style="font-size: 10pt;">MULTI-PASS CRYPTOGRAPHIC ERASE</span>
            </div>

            <div class="qr-container">
                <img class="qr-image" src="data:image/png;base64,{qr_base64}" /><br/>
                <span style="font-size: 10pt; font-weight: bold; color: #E0E0E0;">AUTHENTICITY VERIFIED</span>
            </div>

            <div class="footer-hash">
                SHA-256 HASH:<br/>
                {sha_hash}
            </div>
        </div>
    </body>
    </html>
    """

    # 3. Convert HTML to PDF
    result = BytesIO()
    pisa_status = pisa.CreatePDF(html_template, dest=result)
    
    if pisa_status.err:
        return None
        
    return result.getvalue()
