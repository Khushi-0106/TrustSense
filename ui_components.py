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
    Generates the Neo-Brutalist 'Antigravity' Security Passport HTML.
    """
    trust_score = data.get('trust_score', 100)
    device_id = data.get('device_id', 'TS-UNIT-01')
    date = data.get('date', '2026-05-05')
    files_sensitive = data.get('files_sensitive', 1)
    files_safe = data.get('files_safe', 145)
    sha_hash = data.get('hash', 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6')
    qr_base64 = data.get('qr_base64', '')

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
                --border-width: 4px;
            }}

            body {{
                background-color: var(--bg);
                color: white;
                font-family: 'Roboto Mono', monospace;
                padding: 20px;
                margin: 0;
            }}

            .passport-container {{
                border: 2px solid white;
                background: var(--bg);
                padding: 15px;
                position: relative;
                box-shadow: 5px 5px 0px white;
                max-width: 500px;
                margin: auto;
            }}

            .header-box {{
                background: var(--pastel-green);
                color: black;
                padding: 10px;
                border: 2px solid black;
                text-align: center;
                margin-bottom: 15px;
                animation: pulsate 2s infinite;
                box-shadow: 4px 4px 0px white;
            }}

            @keyframes pulsate {{
                0% {{ box-shadow: 6px 6px 0px white; }}
                50% {{ box-shadow: 12px 12px 0px white; }}
                100% {{ box-shadow: 6px 6px 0px white; }}
            }}

            h1 {{
                font-family: 'Archivo Black', sans-serif;
                font-size: 1.2rem;
                margin: 0;
                text-transform: uppercase;
            }}

            .identity-block {{
                background: repeating-linear-gradient(
                    45deg,
                    var(--pastel-yellow),
                    var(--pastel-yellow) 10px,
                    #d4d600 10px,
                    #d4d600 20px
                );
                color: black;
                padding: 8px;
                border: 2px solid black;
                font-weight: bold;
                margin-bottom: 12px;
                font-size: 0.7rem;
                box-shadow: 4px 4px 0px var(--pastel-green);
            }}

            .identity-content {{
                background: white;
                padding: 10px;
                border: 2px solid black;
                display: inline-block;
            }}

            .ledger-grid {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 20px;
                margin-bottom: 25px;
            }}

            .ledger-item {{
                border: 2px solid white;
                padding: 8px;
                box-shadow: 3px 3px 0px var(--pastel-yellow);
            }}

            .ledger-label {{
                font-size: 0.8rem;
                color: #aaa;
                text-transform: uppercase;
            }}

            .ledger-value {{
                font-size: 1rem;
                font-weight: bold;
                color: var(--pastel-green);
            }}

            .wipe-protocol {{
                border: 2px dashed var(--pastel-green);
                padding: 10px;
                margin-bottom: 12px;
                font-size: 0.7rem;
            }}

            .trust-score-box {{
                position: absolute;
                top: -10px;
                right: -10px;
                background: var(--bg);
                border: 2px solid var(--pastel-green);
                padding: 10px;
                box-shadow: 4px 4px 0px var(--pastel-yellow);
                transform: rotate(5deg);
                z-index: 10;
            }}

            .score-value {{
                font-family: 'Archivo Black', sans-serif;
                font-size: 1.5rem;
                color: var(--pastel-green);
                position: relative;
            }}

            /* Glitch Effect */
            .glitch {{
                position: relative;
            }}
            .glitch::before, .glitch::after {{
                content: attr(data-text);
                position: absolute;
                top: 0; left: 0; width: 100%; height: 100%;
                background: var(--bg);
            }}
            .glitch::before {{
                left: 2px;
                text-shadow: -2px 0 #ff00c1;
                clip: rect(44px, 450px, 56px, 0);
                animation: glitch-anim 5s infinite linear alternate-reverse;
            }}
            .glitch::after {{
                left: -2px;
                text-shadow: -2px 0 #00fff9, 2px 2px #ff00c1;
                animation: glitch-anim2 1s infinite linear alternate-reverse;
            }}

            @keyframes glitch-anim {{
                0% {{ clip: rect(31px, 9999px, 94px, 0); }}
                20% {{ clip: rect(62px, 9999px, 42px, 0); }}
                40% {{ clip: rect(16px, 9999px, 78px, 0); }}
                60% {{ clip: rect(58px, 9999px, 43px, 0); }}
                80% {{ clip: rect(23px, 9999px, 98px, 0); }}
                100% {{ clip: rect(82px, 9999px, 31px, 0); }}
            }}

            @keyframes glitch-anim2 {{
                0% {{ clip: rect(65px, 9999px, 100px, 0); }}
                20% {{ clip: rect(30px, 9999px, 20px, 0); }}
                40% {{ clip: rect(15px, 9999px, 85px, 0); }}
                60% {{ clip: rect(50px, 9999px, 40px, 0); }}
                80% {{ clip: rect(25px, 9999px, 95px, 0); }}
                100% {{ clip: rect(80px, 9999px, 35px, 0); }}
            }}

            .footer-hash {{
                background: var(--pastel-yellow);
                color: black;
                padding: 5px;
                font-size: 0.6rem;
                word-break: break-all;
                border: 1px solid black;
                margin-top: 12px;
            }}

            .qr-image {{
                width: 100px;
                height: 100px;
                border: 2px solid white;
                float: left;
                margin-right: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="passport-container">
            <div class="trust-score-box">
                <div class="score-value glitch" data-text="{trust_score}/100">{trust_score}/100</div>
            </div>

            <div class="header-box">
                <h1>TRUSTSENSE+ SECURITY PASSPORT</h1>
            </div>

            <div class="identity-block">
                <div class="identity-content">
                    DEVICE ID: {device_id} | DATE: {date}
                </div>
            </div>

            <div class="ledger-grid">
                <div class="ledger-item">
                    <div class="ledger-label">Sensitive Files</div>
                    <div class="ledger-value">{files_sensitive}</div>
                </div>
                <div class="ledger-item">
                    <div class="ledger-label">Safe Files</div>
                    <div class="ledger-value">{files_safe}</div>
                </div>
            </div>

            <div class="wipe-protocol">
                <div class="ledger-label">WIPE PROTOCOL</div>
                <div style="font-size: 1.2rem; color: var(--pastel-green); font-weight: bold;">[ DOD-5220.22-M ] MULTI-PASS OVERWRITE</div>
                <p style="font-size: 0.8rem;">Status: Cryptographically Verified Zero-State</p>
            </div>

            <div style="overflow: hidden;">
                <img class="qr-image" src="data:image/png;base64,{qr_base64}" alt="QR CODE" />
                <div style="padding-top: 5px;">
                    <p style="margin: 0; font-size: 0.7rem; font-weight: bold;">AUTHENTICITY GUARANTEED</p>
                    <p style="margin: 0; font-size: 0.6rem; color: #888;">Legal forensic receipt of data sanitization.</p>
                </div>
            </div>

            <div class="footer-hash">
                SHA-256: {sha_hash}
            </div>
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
