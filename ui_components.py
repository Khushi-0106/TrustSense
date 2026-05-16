import streamlit.components.v1 as components
import qrcode
import base64
import socket
from io import BytesIO

def get_local_ip():
    try:
        # Create a dummy socket to detect the preferred interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_qr_base64(url):
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

def get_passport_html(data):
    """
    Generates a Hyper-Premium 'Forensic' Security Passport HTML.
    """
    trust_score = data.get('trust_score', 100)
    device_id = data.get('device_id', 'TS-UNIT-01')
    date = data.get('date', '2026-05-05')
    files_sensitive = data.get('files_sensitive', 1)
    files_safe = data.get('files_safe', 145)
    sha_hash = data.get('hash', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6')
    qr_base64 = data.get('qr_base64', '')
    protocol = data.get('protocol', 'ADVANCED MULTI-PASS')

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@700&family=Inter:wght@400;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --navy: #0a192f;
                --gold: #c5a059;
                --gold-bright: #e2c275;
                --parchment: #fdfaf3;
                --parchment-dark: #f1ebd8;
                --white: #ffffff;
            }}

            body {{
                background-color: #0b1120;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
                font-family: 'Inter', sans-serif;
            }}

            .passport {{
                width: 100%;
                max-width: 580px;
                background-color: var(--parchment);
                border: 4px solid var(--gold);
                position: relative;
                box-shadow: 0 40px 100px -20px rgba(0, 0, 0, 0.7);
                overflow: hidden;
                background-image: 
                    radial-gradient(var(--gold) 0.5px, transparent 0.5px);
                background-size: 20px 20px;
                background-position: 10px 10px;
            }}

            .passport::before {{
                content: "";
                position: absolute;
                top: 0; left: 0; width: 100%; height: 100%;
                background: linear-gradient(135deg, rgba(197, 160, 89, 0.05) 0%, transparent 50%, rgba(197, 160, 89, 0.05) 100%);
                pointer-events: none;
            }}

            .header {{
                background-color: var(--navy);
                color: var(--white);
                padding: 40px 30px;
                border-bottom: 5px solid var(--gold);
                display: flex;
                justify-content: space-between;
                align-items: center;
                position: relative;
            }}

            .header::after {{
                content: "OFFICIAL FORENSIC RECORD";
                position: absolute;
                bottom: 5px;
                right: 30px;
                font-size: 0.5rem;
                letter-spacing: 2px;
                color: var(--gold);
                opacity: 0.8;
            }}

            .header-title h1 {{
                margin: 0;
                font-family: 'Cinzel', serif;
                font-size: 1.8rem;
                letter-spacing: 3px;
                color: var(--gold-bright);
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }}

            .header-title p {{
                margin: 5px 0 0;
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.75rem;
                color: var(--white);
                text-transform: uppercase;
                letter-spacing: 4px;
                opacity: 0.9;
            }}

            .doc-num {{
                text-align: right;
                font-family: 'JetBrains Mono', monospace;
                border-left: 1px solid var(--gold);
                padding-left: 20px;
            }}

            .doc-num span {{
                display: block;
                font-size: 0.6rem;
                color: var(--gold-bright);
                opacity: 0.8;
            }}

            .doc-num strong {{
                font-size: 1.1rem;
                color: var(--white);
            }}

            .content {{
                padding: 35px;
                position: relative;
            }}

            .trust-seal {{
                position: absolute;
                top: 20px;
                right: 30px;
                width: 120px;
                height: 120px;
                border: 2px double var(--gold);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                text-align: center;
                font-family: 'Cinzel', serif;
                font-size: 0.6rem;
                font-weight: 700;
                color: var(--gold);
                transform: rotate(15deg);
                background: rgba(197, 160, 89, 0.03);
                box-shadow: inset 0 0 15px rgba(197, 160, 89, 0.1);
                z-index: 5;
            }}

            .grid {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 25px;
                margin-bottom: 30px;
                position: relative;
                z-index: 10;
            }}

            .label {{
                font-size: 0.7rem;
                font-weight: 700;
                color: #4b5563;
                text-transform: uppercase;
                margin-bottom: 6px;
                letter-spacing: 1px;
            }}

            .value {{
                font-size: 1.2rem;
                font-weight: 700;
                color: var(--navy);
                border-bottom: 1px solid var(--gold-bright);
                padding-bottom: 2px;
            }}

            .protocol-bar {{
                background: var(--navy);
                color: var(--white);
                padding: 20px;
                margin-bottom: 30px;
                border-left: 10px solid var(--gold);
                box-shadow: 5px 5px 15px rgba(0,0,0,0.1);
            }}

            .protocol-bar div:first-child {{
                font-size: 0.65rem;
                color: var(--gold);
                font-weight: bold;
                margin-bottom: 5px;
                text-transform: uppercase;
            }}

            .protocol-bar div:last-child {{
                font-size: 1.1rem;
                font-family: 'JetBrains Mono', monospace;
                letter-spacing: 1px;
            }}

            .stat-container {{
                display: flex;
                gap: 20px;
                margin-bottom: 30px;
            }}

            .stat-card {{
                flex: 1;
                background: var(--parchment-dark);
                border: 1px solid var(--gold);
                padding: 15px;
                text-align: center;
            }}

            .stat-card .label {{ margin-bottom: 10px; color: var(--navy); }}
            .stat-card .value {{ border: none; font-size: 1.5rem; }}

            .footer {{
                background-color: var(--parchment-dark);
                padding: 25px 35px;
                display: flex;
                align-items: center;
                gap: 30px;
                border-top: 2px solid var(--gold);
            }}

            .qr-code {{
                width: 90px;
                height: 90px;
                border: 2px solid var(--navy);
                background: white;
                padding: 5px;
                box-shadow: 3px 3px 0px var(--gold);
            }}

            .mrz {{
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.7rem;
                color: #64748b;
                line-height: 1.4;
                letter-spacing: 2px;
            }}

            .hologram {{
                position: absolute;
                bottom: 10px;
                right: 10px;
                font-size: 2rem;
                opacity: 0.1;
                user-select: none;
            }}
        </style>
    </head>
    <body>
        <div class="passport">
            <div class="header">
                <div class="header-title">
                    <h1>SECURITY PASSPORT</h1>
                    <p>TrustSense Forensic Node</p>
                </div>
                <div class="doc-num">
                    <span>REGISTRY ID</span>
                    <strong>{sha_hash[:16].upper()}</strong>
                </div>
            </div>

            <div class="content">
                <div class="trust-seal">TRUSTSENSE<br>AUTHENTIC<br>FORENSICALLY<br>CLEAN</div>
                
                <div class="grid">
                    <div>
                        <div class="label">Hardware Identity</div>
                        <div class="value">{device_id}</div>
                    </div>
                    <div>
                        <div class="label">Trust Integrity Score</div>
                        <div class="value" style="color: #059669;">{trust_score}% CERTIFIED</div>
                    </div>
                    <div>
                        <div class="label">Certification Date</div>
                        <div class="value">{date}</div>
                    </div>
                    <div>
                        <div class="label">Forensic Audit Result</div>
                        <div class="value">CLEAN / ZERO-BIT</div>
                    </div>
                </div>

                <div class="protocol-bar">
                    <div>Applied Eradication Protocol</div>
                    <div>{protocol} (NIST 800-88)</div>
                </div>

                <div class="stat-container">
                    <div class="stat-card">
                        <div class="label">THREATS PURGED</div>
                        <div class="value" style="color: #dc2626;">{files_sensitive}</div>
                    </div>
                    <div class="stat-card">
                        <div class="label">TOTAL ASSETS</div>
                        <div class="value">{files_sensitive + files_safe}</div>
                    </div>
                </div>
            </div>

            <div class="footer">
                <img class="qr-code" src="data:image/png;base64,{qr_base64}" alt="QR">
                <div class="mrz">
                    P&lt;TSA{device_id.replace('-',''):<20}&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;&lt;<br>
                    {sha_hash[:20].upper()}&lt;&lt;&lt;&lt;&lt;260516&lt;&lt;&lt;&lt;
                </div>
            </div>
            <div class="hologram">🛡️</div>
        </div>
    </body>
    </html>
    """
    return html

def get_verification_portal_html(data, tamper_detected=False):
    """
    Generates the Neo-Brutalist 'Live' Verification Portal HTML.
    """
    status_color = "#FFC9C9" if tamper_detected else "#B2F2BB"
    status_text = "SECURITY BREACH" if tamper_detected else "AUTHENTICITY: 100% VERIFIED"
    border_color = "#FFC9C9" if tamper_detected else "#E0E0E0"
    
    sha_signed = data.get('hash', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6')
    sha_live = sha_signed if not tamper_detected else 'X9Y8Z7W6V5U4T3S2R1Q0P9O8N7M6L5K4'

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <link href="https://fonts.googleapis.com/css2?family=Archivo+Black&family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --bg: #1A1A1A;
                --pastel-green: #B2F2BB;
                --pastel-yellow: #FFF3BF;
                --alert-red: #FFC9C9;
                --accent: {status_color};
            }}

            body {{
                background-color: var(--bg);
                color: white;
                font-family: 'Roboto Mono', monospace;
                margin: 0;
                overflow-x: hidden;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                padding: 20px;
            }}

            #scanner-overlay {{
                position: fixed;
                top: 0; left: 0; width: 100%; height: 100%;
                background: black;
                z-index: 100;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                animation: fadeOut 0.5s forwards 2.5s;
            }}

            @keyframes fadeOut {{
                from {{ opacity: 1; }}
                to {{ opacity: 0; visibility: hidden; }}
            }}

            .progress-container {{
                width: 300px;
                border: 4px solid white;
                padding: 5px;
            }}

            .progress-bar {{
                height: 30px;
                background: var(--pastel-green);
                width: 0%;
                animation: scan 2s forwards ease-in-out;
            }}

            @keyframes scan {{
                0% {{ width: 0%; }}
                50% {{ width: 60%; }}
                100% {{ width: 100%; }}
            }}

            .scan-text {{
                font-family: 'Archivo Black', sans-serif;
                margin-bottom: 10px;
                letter-spacing: 2px;
            }}

            .portal-container {{
                border: 6px solid {border_color};
                width: 100%;
                max-width: 600px;
                padding: 40px;
                box-shadow: 15px 15px 0px {border_color};
                background: var(--bg);
            }}

            .banner {{
                background: var(--accent);
                color: black;
                font-family: 'Archivo Black', sans-serif;
                font-size: 1.8rem;
                padding: 20px;
                text-align: center;
                border: 4px solid black;
                margin-bottom: 30px;
                transform: rotate(-2deg);
                box-shadow: 8px 8px 0px white;
            }}

            .hash-comparison {{
                display: flex;
                flex-direction: column;
                gap: 15px;
                margin-bottom: 30px;
            }}

            .hash-box {{
                border: 3px solid white;
                padding: 15px;
                position: relative;
            }}

            .hash-label {{
                position: absolute;
                top: -12px;
                left: 10px;
                background: black;
                padding: 0 10px;
                font-size: 0.7rem;
                font-weight: bold;
                color: var(--pastel-yellow);
            }}

            .hash-value {{
                font-size: 0.8rem;
                word-break: break-all;
                color: {status_color};
            }}

            .status-card {{
                border: 4px solid var(--pastel-yellow);
                padding: 20px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                box-shadow: 10px 10px 0px var(--pastel-yellow);
            }}

            .badge-text {{
                font-family: 'Archivo Black', sans-serif;
                font-size: 1.5rem;
                color: var(--pastel-yellow);
            }}

            .padlock-box {{
                width: 60px;
                height: 60px;
                border: 4px solid var(--pastel-yellow);
                display: flex;
                align-items: center;
                justify-content: center;
                animation: spin 4s infinite linear;
            }}

            @keyframes spin {{
                from {{ transform: rotateY(0deg); }}
                to {{ transform: rotateY(360deg); }}
            }}

            .security-warning {{
                animation: blink 0.5s infinite alternate;
            }}

            @keyframes blink {{
                from {{ opacity: 1; }}
                to {{ opacity: 0.3; }}
            }}
        </style>
    </head>
    <body>
        <div id="scanner-overlay">
            <div class="scan-text">SCANNING INTEGRITY...</div>
            <div class="progress-container">
                <div class="progress-bar"></div>
            </div>
        </div>

        <div class="portal-container">
            <div class="banner {"security-warning" if tamper_detected else ""}">
                {status_text}
            </div>

            <div class="hash-comparison">
                <div class="hash-box">
                    <span class="hash-label">SIGNED CERTIFICATE HASH</span>
                    <div class="hash-value">{sha_signed}</div>
                </div>
                <div class="hash-box">
                    <span class="hash-label">LIVE SYSTEM HASH</span>
                    <div class="hash-value">{sha_live}</div>
                </div>
            </div>

            <div class="status-card">
                <div>
                    <div style="font-size: 0.7rem; color: #cbd5e1; text-transform: uppercase;">VERDICT</div>
                    <div class="badge-text">{"SAFE FOR RESALE" if not tamper_detected else "TAMPER DETECTED"}</div>
                </div>
                <div class="padlock-box">
                    <div style="font-size: 2rem;">{"🔒" if not tamper_detected else "🚨"}</div>
                </div>
            </div>

            <p style="margin-top: 30px; font-size: 0.7rem; color: #94a3b8; text-align: center;">
                TRUSTSENSE+ FORENSIC VERIFICATION NODE #772-B
            </p>
        </div>
    </body>
    </html>
    """
    return html
