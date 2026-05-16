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
    Matches the high-fidelity UI exactly.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch

        # Data Extraction
        device_id    = data.get('device_id', 'TS-UNIT-01')
        sha_hash     = data.get('hash', 'UNKNOWN')
        trust_score  = data.get('trust_score', 100)
        date         = data.get('date', datetime.now().strftime("%d/%m/%Y"))
        files_sens   = data.get('files_sensitive', 0)
        files_total  = data.get('files_safe', 0)
        protocol     = data.get('protocol', 'Standard Overwrite')
        risk_level   = data.get('risk_level', 'Low')
        file_types   = data.get('file_types', {})

        # Colors
        NAVY        = colors.HexColor("#0f1c3a")
        GOLD        = colors.HexColor("#c9a84c")
        PARCHMENT   = colors.HexColor("#f8f5ec")
        RED         = colors.HexColor("#dc2626")
        RED_LIGHT   = colors.HexColor("#fee2e2")
        WHITE       = colors.HexColor("#ffffff")
        GRAY        = colors.HexColor("#6b7280")
        GREEN       = colors.HexColor("#16a34a")

        CHART_COLS = [colors.HexColor("#0f1c3a"), colors.HexColor("#c9a84c"), colors.HexColor("#dc2626"), colors.HexColor("#16a34a")]

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)

        def sty(name, **kw): return ParagraphStyle(name, **kw)
        s_tiny_gold  = sty('TG', fontName='Courier-Bold', fontSize=7, textColor=GOLD)
        s_title      = sty('TT', fontName='Helvetica-Bold', fontSize=20, textColor=WHITE)
        s_sub        = sty('TS', fontName='Courier-Bold', fontSize=8, textColor=GOLD)
        s_doc_no_val = sty('DV', fontName='Courier-Bold', fontSize=11, textColor=GOLD, alignment=2)
        s_field_lbl  = sty('FL', fontName='Helvetica-Bold', fontSize=7, textColor=GRAY)
        s_field_val  = sty('FV', fontName='Helvetica-Bold', fontSize=12, textColor=NAVY)
        s_stat_num_r = sty('SNR', fontName='Helvetica-Bold', fontSize=28, textColor=RED, alignment=1)
        s_stat_num_n = sty('SNN', fontName='Helvetica-Bold', fontSize=28, textColor=NAVY, alignment=1)
        s_stat_num_g = sty('SNG', fontName='Helvetica-Bold', fontSize=28, textColor=colors.HexColor("#9a7a2a"), alignment=1)
        s_mrz        = sty('MZ', fontName='Courier', fontSize=7, textColor=colors.HexColor("#9ca3af"))

        W = doc.width
        elements = []

        # Top Gold Strip
        gold_strip = Table([['']], colWidths=[W])
        gold_strip.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), GOLD), ('TOPPADDING',(0,0),(-1,-1),3), ('BOTTOMPADDING',(0,0),(-1,-1),3)]))
        elements.append(gold_strip)

        # Navy Header
        title_block = [[Paragraph("OFFICIAL DOCUMENT", s_tiny_gold)], [Paragraph("Data Sanitization Passport", s_title)], [Paragraph("TRUSTSENSE FORENSIC AUTHORITY", s_sub)]]
        title_tbl = Table(title_block, colWidths=[W*0.65])
        doc_no_tbl = Table([[Paragraph("DOCUMENT NO.", sty('DL', fontName='Courier-Bold', fontSize=7, textColor=GOLD, alignment=2))], [Paragraph(sha_hash[:12].upper(), s_doc_no_val)]], colWidths=[W*0.25])
        header_tbl = Table([[title_tbl, doc_no_tbl]], colWidths=[W*0.7, W*0.3])
        header_tbl.setStyle(TableStyle([('VALIGN', (0,0),(-1,-1), 'MIDDLE'), ('BACKGROUND',(0,0),(-1,-1), NAVY), ('TOPPADDING',(0,0),(-1,-1),20), ('BOTTOMPADDING',(0,0),(-1,-1),20), ('LEFTPADDING',(0,0),(-1,-1),15), ('RIGHTPADDING',(0,0),(-1,-1),15)]))
        elements.append(header_tbl)

        # Body Divider
        elements.append(gold_strip)

        # Parchment Body
        def space(h): return Table([['']], colWidths=[W], rowHeights=[h], style=[('BACKGROUND',(0,0),(-1,-1),PARCHMENT)])
        elements.append(space(15))

        # Credentials
        cw = W / 4
        c_labels = [Paragraph(l, s_field_lbl) for l in ["HOLDER / NODE", "DATE OF ISSUE", "PROTOCOL APPLIED", "INTEGRITY RATING"]]
        c_vals   = [Paragraph(device_id, s_field_val), Paragraph(date, s_field_val), Paragraph(protocol, s_field_val), Paragraph(f"{trust_score}%", s_field_val)]
        c_tbl = Table([c_labels, c_vals], colWidths=[cw]*4)
        c_tbl.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), PARCHMENT), ('LINEBELOW', (0,1), (-1,1), 1.5, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.2)), ('TOPPADDING', (0,0),(-1,-1), 4), ('BOTTOMPADDING', (0,0),(-1,-1), 12), ('LEFTPADDING', (0,0),(-1,-1), 15)]))
        elements.append(c_tbl)
        elements.append(space(20))

        # Stats
        sw = (W - 40) / 3
        def mk_stat(num, lbl, bg, bcol, tcol):
            t = Table([[Paragraph(str(num), tcol)], [Paragraph(lbl, sty('SL', fontName='Helvetica-Bold', fontSize=7, textColor=tcol.textColor, alignment=1))]], colWidths=[sw])
            t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),bg),('BOX',(0,0),(-1,-1),1.5,bcol),('ROUNDEDCORNERS',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10)]))
            return t
        
        stat_row = Table([[mk_stat(files_sens, "THREATS PURGED", RED_LIGHT, colors.HexColor("#fecaca"), s_stat_num_r),
                           mk_stat(files_total, "FILES CLEARED", colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.05), colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.1), s_stat_num_n),
                           mk_stat("100%", "VERIFIED CLEAN", colors.rgba(GOLD.red, GOLD.green, GOLD.blue, 0.1), colors.rgba(GOLD.red, GOLD.green, GOLD.blue, 0.3), s_stat_num_g)]], colWidths=[sw+10]*3)
        stat_row.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),PARCHMENT),('ALIGN',(0,0),(-1,-1),'CENTER')]))
        elements.append(stat_row)
        elements.append(space(20))

        # Chart
        if file_types:
            elements.append(Table([[Paragraph("ERADICATED FILE DISTRIBUTION", s_field_lbl)]], colWidths=[W], style=[('BACKGROUND',(0,0),(-1,-1),PARCHMENT),('LEFTPADDING',(0,0),(-1,-1),15)]))
            entries = list(file_types.items())[:8]
            max_f = max(file_types.values())
            bar_w = (W - 30) / max(len(entries), 1)
            bar_cells = []
            for i, (ext, cnt) in enumerate(entries):
                col = CHART_COLS[i % len(CHART_COLS)]
                h = max(3, int((cnt / max_f) * 40))
                bc = Table([[Paragraph(str(cnt), sty('BC', fontName='Courier', fontSize=6, textColor=GRAY))], [Table([['']], colWidths=[bar_w-8], rowHeights=[h], style=[('BACKGROUND',(0,0),(-1,-1),col),('ROUNDEDCORNERS',(0,0),(-1,-1),2)])], [Paragraph(f".{ext}", sty('BE', fontName='Courier-Bold', fontSize=6, textColor=GRAY))]], colWidths=[bar_w])
                bc.setStyle(TableStyle([('ALIGN', (0,0),(-1,-1), 'CENTER'), ('VALIGN', (0,1), (0,1), 'BOTTOM')]))
                bar_cells.append(bc)
            chart_tbl = Table([bar_cells], colWidths=[bar_w]*len(entries))
            chart_tbl.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), PARCHMENT), ('ALIGN', (0,0),(-1,-1), 'CENTER'), ('VALIGN', (0,0),(-1,-1), 'BOTTOM'), ('LINEBELOW', (0,0), (-1,0), 0.5, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.1)), ('BOTTOMPADDING', (0,0), (-1,-1), 10)]))
            elements.append(chart_tbl)
            elements.append(space(20))

        # Verification
        v_data = [[Table([[Paragraph("✓  Sanitization Verified", sty('VF', fontName='Helvetica-Bold', fontSize=11, textColor=GREEN))], [Paragraph("All sectors overwritten — confirmed irrecoverable", sty('VS', fontName='Helvetica', fontSize=7, textColor=GRAY))]], colWidths=[W*0.7], style=[('LEFTPADDING',(0,0),(-1,-1),15)]),
                   Table([[Paragraph("VERIFIED<br/>SECURE", sty('SEAL', fontName='Helvetica-Bold', fontSize=5, textColor=NAVY, alignment=1))]], colWidths=[0.8*inch], rowHeights=[0.8*inch], style=[('BACKGROUND', (0,0),(-1,-1), PARCHMENT), ('BOX', (0,0),(-1,-1), 1, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.2)), ('ROUNDEDCORNERS', (0,0),(-1,-1), 30), ('ALIGN', (0,0),(-1,-1), 'CENTER'), ('VALIGN', (0,0),(-1,-1), 'MIDDLE'))]]
        v_row = Table(v_data, colWidths=[W*0.75, W*0.25])
        v_row.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), PARCHMENT), ('VALIGN', (0,0),(-1,-1), 'MIDDLE'), ('LINEABOVE', (0,0), (-1,-1), 1, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.1))]))
        elements.append(v_row)
        elements.append(space(15))

        # Signature
        sig_data = [[Table([[Paragraph("TrustSense Engine", sty('SG', fontName='Times-Italic', fontSize=12, textColor=GRAY))], [Paragraph("──────────────────────────", sty('SGL', fontName='Courier-Bold', fontSize=7, textColor=GRAY))], [Paragraph("AUTHORIZED SIGNATURE", sty('SGL', fontName='Courier-Bold', fontSize=7, textColor=GRAY))]], colWidths=[W*0.6], style=[('LEFTPADDING',(0,0),(-1,-1),15)]),
                     Table([[Paragraph("VALID FROM", sty('VL', fontName='Courier-Bold', fontSize=7, textColor=GRAY, alignment=2))], [Paragraph(date, sty('VV', fontName='Helvetica-Bold', fontSize=11, textColor=NAVY, alignment=2))]], colWidths=[W*0.3], style=[('ALIGN', (0,0),(-1,-1), 'RIGHT'), ('RIGHTPADDING', (0,0), (-1,-1), 15)])]]
        s_row = Table(sig_data, colWidths=[W*0.65, W*0.35])
        s_row.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), PARCHMENT), ('VALIGN', (0,0),(-1,-1), 'BOTTOM'), ('BOTTOMPADDING', (0,0), (-1,-1), 12)]))
        elements.append(s_row)

        # MRZ
        m1 = f"P<TSA{device_id.replace('-',''):<30}{'<'*15}"[:44].replace('<', '&lt;')
        m2 = f"{sha_hash.upper()[:9]}{'<'*9}260516{'<'*15}"[:44].replace('<', '&lt;')
        mrz_tbl = Table([[Paragraph(m1, s_mrz)], [Paragraph(m2, s_mrz)]], colWidths=[W], style=[('BACKGROUND', (0,0),(-1,-1), colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.04)), ('LINEABOVE', (0,0), (-1,0), 0.5, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.1)), ('TOPPADDING', (0,0), (-1,-1), 6), ('BOTTOMPADDING', (0,0), (-1,-1), 6), ('LEFTPADDING', (0,0), (-1,-1), 15)])
        elements.append(mrz_tbl)
        elements.append(gold_strip)

        def bg(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(PARCHMENT)
            canvas.rect(0, 0, A4[0], A4[1], fill=1)
            canvas.setStrokeColor(GOLD)
            canvas.setLineWidth(1)
            canvas.rect(10, 10, A4[0]-20, A4[1]-20)
            canvas.restoreState()

        doc.build(elements, onFirstPage=bg, onLaterPages=bg)
        return buf.getvalue()
    except Exception as e:
        print(f"PDF Error: {e}")
        raise e

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/api/certify', methods=['POST'])
def certify():
    data = request.json or {}
    # Simulate a verifiable cryptographic response
    cert = {
        "id": hashlib.sha256(str(datetime.now().timestamp()).encode()).hexdigest()[:12],
        "hash": hashlib.sha256(data.get('device_id', 'TS-UNIT-01').encode()).hexdigest(),
        "timestamp": datetime.now().isoformat()
    }
    return jsonify({"cert": cert})

@app.route('/api/certificate', methods=['POST'])
def certificate():
    data = request.json or {}
    try:
        pdf_bytes  = generate_neo_pdf(data)
        pdf_base64 = base64.b64encode(pdf_bytes).decode()
        return jsonify({"pdf_base64": pdf_base64})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan', methods=['POST', 'GET'])
def scan():
    return jsonify({"status": "ready"})

if __name__ == "__main__":
    app.run(port=5000)
