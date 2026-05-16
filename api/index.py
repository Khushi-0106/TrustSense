import os
import sys
import base64
import hashlib
from datetime import datetime
from io import BytesIO
from flask import Flask, request, jsonify
from flask_cors import CORS

# Add parent directory so processing/ and core/ are importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from processing.neo_pdf import generate_neo_pdf as _gen_pdf
    _PDF_MODULE = True
except Exception:
    _PDF_MODULE = False

app = Flask(__name__)
CORS(app)

# ── Inline: Certificate ────────────────────────────────────────────────────────
def generate_certificate(device_id, trust_score, wipe_level):
    now = str(datetime.utcnow())
    raw = f"{device_id}{now}{trust_score}{wipe_level}"
    return {
        "device_id": device_id,
        "timestamp": now,
        "trust_score": trust_score,
        "wipe_level": wipe_level,
        "hash": hashlib.sha256(raw.encode()).hexdigest()
    }

# ── Inline: PDF Generation ─────────────────────────────────────────────────────
def generate_neo_pdf(data):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.graphics.barcode import code128
        import qrcode

        device_id    = data.get('device_id', 'TS-UNIT-01')
        sha_hash     = data.get('hash', 'UNKNOWN')
        trust_score  = data.get('trust_score', 100)
        date         = data.get('date', datetime.now().strftime("%Y-%m-%d"))
        files_sens   = data.get('files_sensitive', 0)
        files_safe   = data.get('files_safe', 0)
        protocol     = data.get('protocol', 'Standard Overwrite')
        risk_level   = data.get('risk_level', 'Low')
        file_types   = data.get('file_types', {})

        bg_dark      = colors.HexColor("#050B14")
        trust_green  = colors.HexColor("#10B981")
        trust_cyan   = colors.HexColor("#06B6D4")
        trust_yellow = colors.HexColor("#FBBF24")
        text_white   = colors.HexColor("#FFFFFF")
        text_gray    = colors.HexColor("#9CA3AF")

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)

        s_title   = ParagraphStyle('T', fontName='Helvetica-Bold',   fontSize=22, textColor=bg_dark,     alignment=1)
        s_sub     = ParagraphStyle('S', fontName='Courier-Bold',     fontSize=9,  textColor=bg_dark,     alignment=1, leading=13)
        s_label   = ParagraphStyle('L', fontName='Courier-Bold',     fontSize=8,  textColor=text_gray,   leading=12)
        s_mono_g  = ParagraphStyle('G', fontName='Courier-Bold',     fontSize=10, textColor=trust_green, leading=13)
        s_mono_y  = ParagraphStyle('Y', fontName='Courier-Bold',     fontSize=9,  textColor=trust_yellow,leading=13, alignment=1)
        s_mono_c  = ParagraphStyle('C', fontName='Courier-Bold',     fontSize=9,  textColor=trust_cyan,  leading=13)
        s_sig     = ParagraphStyle('I', fontName='Times-Italic',     fontSize=13, textColor=text_gray,   alignment=1)

        elements = []

        # Header
        h_data = [
            [Paragraph("DATA SANITIZATION CERTIFICATE", s_title)],
            [Paragraph(f"TrustSense Forensic Verification Report  ·  {date}", s_sub)]
        ]
        h_table = Table(h_data, colWidths=[doc.width])
        h_table.setStyle(TableStyle([
            ('BACKGROUND',    (0,0),(-1,-1), trust_green),
            ('BOX',           (0,0),(-1,-1), 3, text_white),
            ('TOPPADDING',    (0,0),(-1,-1), 18),
            ('BOTTOMPADDING', (0,0),(-1,-1), 18),
        ]))
        elements.append(h_table)
        elements.append(Spacer(1, 18))

        # Barcode + ID
        try:
            bc = code128.Code128(sha_hash[:12], barHeight=0.35*inch, barWidth=1.1)
        except Exception:
            bc = Paragraph(sha_hash[:12], s_mono_y)
        id_data = [[bc, Paragraph(f"CERT ID: {sha_hash[:12]}<br/>NODE: {device_id}<br/>RISK: {risk_level}", s_mono_y)]]
        id_tbl = Table(id_data, colWidths=[doc.width*0.5, doc.width*0.5])
        id_tbl.setStyle(TableStyle([
            ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
            ('BOX',    (0,0),(-1,-1), 1, text_gray),
            ('PADDING',(0,0),(-1,-1), 10),
        ]))
        elements.append(id_tbl)
        elements.append(Spacer(1, 22))

        # Metric cards
        def mk_box(lbl, val, col):
            return Table([[Paragraph(lbl, s_label)],
                          [Paragraph(str(val), ParagraphStyle('V', fontName='Helvetica-Bold', fontSize=30, textColor=col))]],
                         colWidths=[doc.width/2.1])

        m_data = [[mk_box("THREATS PURGED", files_sens, trust_green), mk_box("FILES PROCESSED", files_safe, trust_cyan)]]
        m_tbl = Table(m_data, colWidths=[doc.width/2, doc.width/2])
        m_tbl.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),0),('RIGHTPADDING',(0,0),(-1,-1),0)]))
        elements.append(m_tbl)
        elements.append(Spacer(1, 22))

        # Protocol table
        p_data = [
            [Paragraph("PROTOCOL DEPLOYED",  s_label), Paragraph(protocol,          s_mono_g)],
            [Paragraph("INTEGRITY SCORE",     s_label), Paragraph(f"{trust_score}% SECURE", ParagraphStyle('SC', fontName='Helvetica-Bold', fontSize=20, textColor=trust_green))],
            [Paragraph("TIMESTAMP (UTC)",     s_label), Paragraph(date,              s_mono_c)],
        ]
        p_tbl = Table(p_data, colWidths=[doc.width*0.38, doc.width*0.62])
        p_tbl.setStyle(TableStyle([
            ('LINEBELOW', (0,0),(-1,-2), 0.5, colors.Color(1,1,1,alpha=0.08)),
            ('TOPPADDING',(0,0),(-1,-1), 13),('BOTTOMPADDING',(0,0),(-1,-1), 13),
            ('VALIGN',   (0,0),(-1,-1), 'MIDDLE'),
        ]))
        elements.append(p_tbl)
        elements.append(Spacer(1, 22))

        # File type bar chart (drawn as table cells)
        if file_types:
            total_files = max(sum(file_types.values()), 1)
            bar_colors  = [trust_green, trust_cyan, trust_yellow,
                           colors.HexColor("#A855F7"), colors.HexColor("#3B82F6"),
                           colors.HexColor("#F97316"), colors.HexColor("#EF4444")]
            chart_label = [Paragraph("ERADICATED FILE DISTRIBUTION", s_label)]
            chart_label_tbl = Table([chart_label], colWidths=[doc.width])
            elements.append(chart_label_tbl)
            elements.append(Spacer(1, 6))

            bar_row = []
            lbl_row = []
            for i, (ext, cnt) in enumerate(list(file_types.items())[:7]):
                pct     = (cnt / total_files)
                bc_col  = bar_colors[i % len(bar_colors)]
                bar_row.append(Paragraph("█" * max(1, int(pct * 30)), ParagraphStyle('Bar', fontName='Courier', fontSize=7, textColor=bc_col)))
                lbl_row.append(Paragraph(f".{ext}<br/>{cnt}", ParagraphStyle('BL', fontName='Courier', fontSize=6, textColor=text_gray, alignment=1)))

            col_w = doc.width / max(len(bar_row), 1)
            chart_tbl = Table([bar_row, lbl_row], colWidths=[col_w]*len(bar_row))
            chart_tbl.setStyle(TableStyle([('ALIGN',(0,0),(-1,-1),'CENTER'),('VALIGN',(0,0),(-1,-1),'BOTTOM')]))
            elements.append(chart_tbl)
            elements.append(Spacer(1, 22))

        # QR + Signature
        try:
            verify_url = f"https://trust-sense.vercel.app/?verify=true&id={device_id}&hash={sha_hash}"
            qr = qrcode.QRCode(version=1, box_size=8, border=2)
            qr.add_data(verify_url)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="#10B981", back_color="#050B14")
            qr_buf = BytesIO(); qr_img.save(qr_buf); qr_buf.seek(0)
            qr_rl = Image(qr_buf, width=1.4*inch, height=1.4*inch)
        except Exception:
            qr_rl = Paragraph("QR N/A", s_label)

        sig_data = [[qr_rl, Paragraph("<i>TrustSense Cryptographic Engine</i><br/><br/>______________________________<br/>AUTHORIZED SIGNATURE", s_sig)]]
        sig_tbl = Table(sig_data, colWidths=[doc.width*0.28, doc.width*0.72])
        sig_tbl.setStyle(TableStyle([('VALIGN',(0,0),(-1,-1),'MIDDLE'),('ALIGN',(1,0),(1,0),'CENTER')]))
        elements.append(sig_tbl)
        elements.append(Spacer(1, 24))

        # SHA ribbon
        ribbon_data = [[Paragraph(f"SHA-256: {sha_hash}", ParagraphStyle('H', fontName='Courier-Bold', fontSize=7, textColor=bg_dark, alignment=1))]]
        ribbon_tbl  = Table(ribbon_data, colWidths=[doc.width])
        ribbon_tbl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),trust_yellow),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7)]))
        elements.append(ribbon_tbl)

        # Background
        def bg(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(bg_dark)
            canvas.rect(0, 0, A4[0], A4[1], fill=1)
            canvas.setStrokeColor(colors.Color(0.023, 0.713, 0.831, alpha=0.04))
            canvas.setLineWidth(0.5)
            for i in range(0, int(A4[0]), 20): canvas.line(i, 0, i, A4[1])
            for i in range(0, int(A4[1]), 20): canvas.line(0, i, A4[0], i)
            canvas.setStrokeColor(trust_green); canvas.setLineWidth(3)
            canvas.rect(12, 12, A4[0]-24, A4[1]-24)
            canvas.restoreState()

        doc.build(elements, onFirstPage=bg, onLaterPages=bg)
        return buf.getvalue()

    except ImportError as e:
        raise RuntimeError(f"Missing dependency: {e}. Ensure reportlab and qrcode are in requirements.txt.")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return jsonify({"status": "online", "platform": "TrustSense+ API"})

@app.route('/api/certify', methods=['POST'])
def certify():
    data = request.json or {}
    cert = generate_certificate(
        data.get('device_id', 'TS-UNIT-01'),
        data.get('trust_score', 100),
        data.get('wipe_level', 'Standard Wipe')
    )
    return jsonify({"cert": cert})

@app.route('/api/certificate', methods=['POST'])
def certificate():
    data = request.json or {}
    try:
        # Prefer the clean module version; fall back to inlined
        fn = _gen_pdf if _PDF_MODULE else generate_neo_pdf
        pdf_bytes  = fn(data)
        pdf_base64 = base64.b64encode(pdf_bytes).decode()
        return jsonify({"pdf_base64": pdf_base64})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan', methods=['POST', 'GET'])
def scan():
    """Lightweight stub — real scanning is done client-side via File System Access API."""
    data = request.json or {}
    return jsonify({
        "results": {
            "total_files": data.get('total_files', 0),
            "sensitive_files": data.get('sensitive_files', 0),
            "risk_level": data.get('risk_level', 'Low'),
            "file_types": data.get('file_types', {})
        },
        "score": data.get('trust_score', 100),
        "recommendation": data.get('recommendation', 'Standard Wipe')
    })
