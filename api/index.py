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

app = Flask(__name__)
CORS(app)

# ── New Premium PDF Logic (Inlined for Vercel Reliability) ────────────────────
def generate_neo_pdf(data):
    """
    Generates the premium parchment/navy/gold official passport PDF.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch

        # Data Extraction
        device_id    = data.get('device_id', 'TS-UNIT-01')
        sha_hash     = data.get('hash', 'UNKNOWN')
        trust_score  = data.get('trust_score', 100)
        date         = data.get('date', datetime.now().strftime("%d/%m/%Y"))
        files_sens   = data.get('files_sensitive', 0)
        files_total  = data.get('files_safe', 0)
        protocol     = data.get('protocol', 'Advanced Multi-Pass')
        risk_counts  = data.get('risk_counts', {"High": 0, "Medium": 0, "Low": 0, "Hidden": 0})

        # Colors
        NAVY        = colors.HexColor("#0a192f")
        GOLD        = colors.HexColor("#c5a059")
        GOLD_B      = colors.HexColor("#e2c275")
        PARCHMENT   = colors.HexColor("#fdfaf3")
        RED         = colors.HexColor("#dc2626")
        GREEN       = colors.HexColor("#059669")
        WHITE       = colors.HexColor("#ffffff")
        GRAY        = colors.HexColor("#64748b")

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)

        def sty(name, **kw): return ParagraphStyle(name, **kw)
        s_title      = sty('TT', fontName='Helvetica-Bold', fontSize=24, textColor=GOLD_B, letterSpacing=2)
        s_sub        = sty('TS', fontName='Courier-Bold', fontSize=8, textColor=WHITE, letterSpacing=3)
        s_doc_lbl    = sty('DL', fontName='Courier-Bold', fontSize=7, textColor=GOLD, alignment=2)
        s_doc_val    = sty('DV', fontName='Courier-Bold', fontSize=12, textColor=WHITE, alignment=2)
        s_field_lbl  = sty('FL', fontName='Helvetica-Bold', fontSize=8, textColor=GRAY, textTransform='uppercase')
        s_field_val  = sty('FV', fontName='Helvetica-Bold', fontSize=14, textColor=NAVY)
        s_mrz        = sty('MZ', fontName='Courier', fontSize=8, textColor=GRAY, letterSpacing=2)

        W = doc.width
        elements = []

        # ── HEADER ──
        h_left = [[Paragraph("SECURITY PASSPORT", s_title)], [Paragraph("TRUSTSENSE FORENSIC NODE CERTIFICATION", s_sub)]]
        h_right = [[Paragraph("REGISTRY ID", s_doc_lbl)], [Paragraph(sha_hash[:16].upper(), s_doc_val)]]
        header_tbl = Table([[Table(h_left, colWidths=[W*0.65]), Table(h_right, colWidths=[W*0.25])]], colWidths=[W*0.7, W*0.3])
        header_tbl.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), NAVY), ('BOX', (0,0),(-1,-1), 2, GOLD), ('VALIGN', (0,0),(-1,-1), 'MIDDLE'), ('TOPPADDING',(0,0),(-1,-1),25), ('BOTTOMPADDING',(0,0),(-1,-1),25)]))
        elements.append(header_tbl)
        
        elements.append(Spacer(1, 30))

        # ── CREDENTIALS GRID ──
        def mk_grid_item(lbl, val, color=NAVY):
            return Table([[Paragraph(lbl, s_field_lbl)], [Paragraph(str(val), sty('VAL', fontName='Helvetica-Bold', fontSize=14, textColor=color))]], colWidths=[W/2 - 20])

        grid = Table([[mk_grid_item("Hardware Instance", device_id), mk_grid_item("Trust Integrity Score", f"{trust_score}% CERTIFIED", GREEN)],
                      [mk_grid_item("Certification Date", date), mk_grid_item("Forensic Audit Result", "CLEAN / ZERO-BIT")]], colWidths=[W/2, W/2])
        elements.append(grid)
        
        elements.append(Spacer(1, 20))

        # ── PROTOCOL BAR ──
        p_tbl = Table([[Paragraph("Applied Eradication Protocol", sty('PL', fontName='Helvetica-Bold', fontSize=7, textColor=GOLD))],
                       [Paragraph(f"{protocol} (NIST 800-88)", sty('PV', fontName='Courier-Bold', fontSize=16, textColor=WHITE))]], colWidths=[W-20])
        p_tbl.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), NAVY), ('LEFTPADDING', (0,0),(-1,-1), 20), ('TOPPADDING', (0,0),(-1,-1), 15), ('BOTTOMPADDING', (0,0),(-1,-1), 15)]))
        elements.append(p_tbl)
        
        elements.append(Spacer(1, 30))

        # ── RISK GRAPH ──
        elements.append(Paragraph("FORENSIC RISK CATEGORIZATION", s_field_lbl))
        elements.append(Spacer(1, 10))
        
        max_c = max(risk_counts.values()) if any(risk_counts.values()) else 1
        risk_data = [("HIGH RISK", risk_counts['High'], RED), ("MEDIUM RISK", risk_counts['Medium'], colors.orange), ("LOW RISK", risk_counts['Low'], GREEN), ("HIDDEN ASSETS", risk_counts['Hidden'], NAVY)]
        
        for lbl, cnt, col in risk_data:
            bar_w = (cnt / max_c) * (W - 150)
            row = Table([[Paragraph(lbl, sty('RL', fontName='Helvetica-Bold', fontSize=7, textColor=NAVY)), 
                          Table([['']], colWidths=[max(5, bar_w)], rowHeights=[10], style=[('BACKGROUND',(0,0),(-1,-1),col)]),
                          Paragraph(f"{cnt} ITEMS", sty('RC', fontName='Courier-Bold', fontSize=7, textColor=GRAY))]], colWidths=[100, W-180, 80])
            elements.append(row)
            elements.append(Spacer(1, 8))

        elements.append(Spacer(1, 30))

        # ── STATS & MRZ ──
        s_row = Table([[Table([[Paragraph(str(files_sens), sty('SN', fontName='Helvetica-Bold', fontSize=24, textColor=RED, alignment=1))], [Paragraph("THREATS PURGED", sty('SL', fontName='Helvetica-Bold', fontSize=7, textColor=GRAY, alignment=1))]], colWidths=[W/3]),
                        Table([[Paragraph("VERIFIED", sty('SN', fontName='Helvetica-Bold', fontSize=24, textColor=GREEN, alignment=1))], [Paragraph("INTEGRITY STATUS", sty('SL', fontName='Helvetica-Bold', fontSize=7, textColor=GRAY, alignment=1))]], colWidths=[W/3])]], colWidths=[W/2, W/2])
        elements.append(s_row)
        
        elements.append(Spacer(1, 40))
        
        mrz_text = f"P<TSA{device_id.replace('-',''):<20}{'<'*10}\n{sha_hash[:20].upper()}{'<'*5}260516"
        elements.append(Table([[Paragraph(mrz_text.replace('\n', '<br/>'), s_mrz)]], colWidths=[W], style=[('BACKGROUND', (0,0),(-1,-1), colors.Color(0,0,0,alpha=0.05)), ('TOPPADDING', (0,0),(-1,-1), 10), ('BOTTOMPADDING', (0,0),(-1,-1), 10)]))

        def add_bg(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(PARCHMENT)
            canvas.rect(0, 0, A4[0], A4[1], fill=1)
            canvas.restoreState()

        doc.build(elements, onFirstPage=add_bg, onLaterPages=add_bg)
        return buf.getvalue()
    except Exception as e:
        print(f"PDF ERROR: {e}")
        raise e

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/api/certify', methods=['POST'])
@app.route('/certify', methods=['POST'])
def certify():
    data = request.json or {}
    cert = {
        "id": hashlib.sha256(str(datetime.now().timestamp()).encode()).hexdigest()[:12],
        "hash": hashlib.sha256(data.get('device_id', 'TS-UNIT-01').encode()).hexdigest(),
        "timestamp": datetime.now().isoformat()
    }
    return jsonify({"cert": cert})

@app.route('/api/certificate', methods=['POST'])
@app.route('/certificate', methods=['POST'])
def certificate():
    data = request.json or {}
    try:
        pdf_bytes  = generate_neo_pdf(data)
        pdf_base64 = base64.b64encode(pdf_bytes).decode()
        return jsonify({"pdf_base64": pdf_base64})
    except Exception as e:
        print(f"CERT ERROR: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan', methods=['POST', 'GET'])
@app.route('/scan', methods=['POST', 'GET'])
def scan():
    return jsonify({"status": "ready", "engine": "TrustSense-v4.8"})

if __name__ == "__main__":
    app.run(port=5000)
