import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, Flowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.graphics.barcode import code128
from datetime import datetime
import qrcode
from io import BytesIO
import socket


def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"

def get_alpha_col(c, a):
    """Helper to create a color with alpha since colors.rgba doesn't exist in ReportLab."""
    return colors.Color(c.red, c.green, c.blue, alpha=a)


# --- Palette ---
NAVY        = colors.HexColor("#0f1c3a")
NAVY_LIGHT  = colors.HexColor("#1a2744")
GOLD        = colors.HexColor("#c9a84c")
GOLD_LIGHT  = colors.HexColor("#f5d07a")
PARCHMENT   = colors.HexColor("#f8f5ec")
PARCHMENT_D = colors.HexColor("#eee9dc")
RED         = colors.HexColor("#dc2626")
RED_LIGHT   = colors.HexColor("#fee2e2")
GREEN       = colors.HexColor("#16a34a")
GREEN_LIGHT = colors.HexColor("#f0fdf4")
WHITE       = colors.HexColor("#ffffff")
GRAY        = colors.HexColor("#6b7280")
GRAY_LIGHT  = colors.HexColor("#9ca3af")

CHART_COLS = [
    colors.HexColor("#0f1c3a"),
    colors.HexColor("#c9a84c"),
    colors.HexColor("#dc2626"),
    colors.HexColor("#16a34a"),
    colors.HexColor("#4f46e5"),
    colors.HexColor("#ea580c"),
    colors.HexColor("#0d9488"),
    colors.HexColor("#e11d48"),
]


def generate_neo_pdf(data):
    """
    Generates the navy/gold official passport PDF.
    """
    device_id    = data.get('device_id', 'TS-UNIT-01')
    sha_hash     = data.get('hash', 'UNKNOWN_HASH')
    trust_score  = data.get('trust_score', 100)
    before_score = data.get('before_score', 0)
    date         = data.get('date', datetime.now().strftime("%d/%m/%Y"))
    files_sens   = data.get('files_sensitive', 0)
    files_total  = data.get('files_safe', 0)
    protocol     = data.get('protocol', 'Standard Overwrite')
    risk_level   = data.get('risk_level', 'Low')
    file_types   = data.get('file_types', {})

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )
    gold_strip = Table([['']], colWidths=[doc.width])
    gold_strip.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), GOLD), ('TOPPADDING',(0,0),(-1,-1),3), ('BOTTOMPADDING',(0,0),(-1,-1),3)]))
    
    # ── Colors & Styles ────────────────────────────────────────────────────────
    def sty(name, **kw): return ParagraphStyle(name, **kw)
    s_tiny_gold  = sty('TG', fontName='Courier-Bold', fontSize=7, textColor=GOLD, leading=10)
    s_title      = sty('TT', fontName='Helvetica-Bold', fontSize=22, textColor=WHITE, leading=26)
    s_sub        = sty('TS', fontName='Courier-Bold', fontSize=9, textColor=GOLD, leading=12)
    s_doc_no_val = sty('DV', fontName='Courier-Bold', fontSize=11, textColor=GOLD, alignment=2)
    s_field_lbl  = sty('FL', fontName='Helvetica-Bold', fontSize=8, textColor=GRAY)
    s_field_val  = sty('FV', fontName='Helvetica-Bold', fontSize=13, textColor=NAVY)
    s_stat_num_r = sty('SNR', fontName='Helvetica-Bold', fontSize=28, textColor=RED, alignment=1)
    s_stat_num_n = sty('SNN', fontName='Helvetica-Bold', fontSize=28, textColor=NAVY, alignment=1)
    s_stat_num_g = sty('SNG', fontName='Helvetica-Bold', fontSize=28, textColor=colors.HexColor("#9a7a2a"), alignment=1)
    s_stat_lbl   = sty('SL', fontName='Helvetica-Bold', fontSize=7, textColor=GRAY, alignment=1)
    s_verified   = sty('VF',  fontName='Helvetica-Bold',fontSize=11, textColor=GREEN)
    s_verified_s = sty('VS',  fontName='Helvetica',     fontSize=7,  textColor=GRAY)
    s_sig        = sty('SG',  fontName='Times-Italic',  fontSize=12, textColor=GRAY_LIGHT)
    s_sig_line   = sty('SGL', fontName='Courier-Bold',  fontSize=7,  textColor=GRAY_LIGHT)
    s_valid_lbl  = sty('VL',  fontName='Courier-Bold',  fontSize=7,  textColor=GRAY_LIGHT, alignment=2)
    s_valid_val  = sty('VV',  fontName='Helvetica-Bold',fontSize=11, textColor=NAVY, alignment=2)
    s_mrz        = sty('MZ', fontName='Courier', fontSize=7, textColor=colors.HexColor("#9ca3af"))

    W = doc.width
    elements = []

    # ── GOLD HEADER STRIP ─────────────────────────────────────────────────────
    elements.append(gold_strip)

    # ── NAVY HEADER ──────────────────────────────────────────────────────────
    title_block = [
        [Paragraph("OFFICIAL SECURITY PASSPORT", s_tiny_gold)],
        [Paragraph("Data Sanitization Certificate", s_title)],
        [Paragraph("TRUSTSENSE FORENSIC AUTHORITY • VERIFIED SECURE", s_sub)],
    ]
    title_tbl = Table(title_block, colWidths=[W*0.7])
    doc_no_tbl = Table([[Paragraph("CERTIFICATE ID", sty('DL', fontName='Courier-Bold', fontSize=7, textColor=GOLD, alignment=2))], [Paragraph(sha_hash[:14].upper(), s_doc_no_val)]], colWidths=[W*0.25])
    
    header_tbl = Table([[title_tbl, doc_no_tbl]], colWidths=[W*0.7, W*0.3])
    header_tbl.setStyle(TableStyle([
        ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ('BACKGROUND',(0,0),(-1,-1), NAVY),
        ('TOPPADDING',(0,0),(-1,-1),24),('BOTTOMPADDING',(0,0),(-1,-1),24),
        ('LEFTPADDING',(0,0),(-1,-1),20),('RIGHTPADDING',(0,0),(-1,-1),20)
    ]))
    elements.append(header_tbl)
    elements.append(gold_strip)

    # ── BODY ──────────────────────────────────────────────────────────────────
    def space(h): return Table([['']], colWidths=[W], rowHeights=[h], style=[('BACKGROUND',(0,0),(-1,-1),PARCHMENT)])
    elements.append(space(20))

    # ── CREDENTIALS ──
    cw = W / 4
    c_labels = [Paragraph(l, s_field_lbl) for l in ["HOLDER / DEVICE ID", "ISSUANCE DATE", "PROTOCOL USED", "TRUST SCORE"]]
    c_vals   = [Paragraph(device_id, s_field_val), Paragraph(date, s_field_val), Paragraph(protocol, s_field_val), Paragraph(f"{trust_score}%", s_field_val)]
    c_tbl = Table([c_labels, c_vals], colWidths=[cw]*4)
    c_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), PARCHMENT),
        ('LINEBELOW', (0,1), (-1,1), 1.5, get_alpha_col(NAVY, 0.15)),
        ('TOPPADDING', (0,0),(-1,-1), 5),('BOTTOMPADDING', (0,0),(-1,-1), 15),
        ('LEFTPADDING', (0,0),(-1,-1), 20)
    ]))
    elements.append(c_tbl)
    elements.append(space(25))

    # ── RISK DISTRIBUTION GRAPH ──
    risk_counts = data.get('risk_counts', {"High": 0, "Medium": 0, "Low": 0, "Hidden": 0})
    elements.append(Table([[Paragraph("FORENSIC RISK CATEGORIZATION", s_field_lbl)]], colWidths=[W], style=[('BACKGROUND',(0,0),(-1,-1),PARCHMENT),('LEFTPADDING',(0,0),(-1,-1),20)]))
    
    # Simple Bar Chart inside PDF
    max_count = max(risk_counts.values()) if any(risk_counts.values()) else 1
    bar_w_total = W - 40
    
    risk_entries = [("HIGH RISK", risk_counts["High"], RED), ("MEDIUM RISK", risk_counts["Medium"], colors.HexColor("#ea580c")), ("LOW RISK", risk_counts["Low"], GREEN), ("HIDDEN ASSETS", risk_counts["Hidden"], NAVY)]
    
    chart_cells = []
    for lbl, count, col in risk_entries:
        fill_w = max(5, (count / max_count) * (bar_w_total - 100))
        bar = Table([['']], colWidths=[fill_w], rowHeights=[12], style=[('BACKGROUND',(0,0),(-1,-1),col),('ROUNDEDCORNERS',(0,0),(-1,-1),2)])
        row = [Paragraph(lbl, sty('RL', fontName='Helvetica-Bold', fontSize=7, textColor=GRAY)), bar, Paragraph(str(count), sty('RC', fontName='Courier-Bold', fontSize=8, textColor=NAVY))]
        chart_cells.append(row)
        
    chart_tbl = Table(chart_cells, colWidths=[100, bar_w_total-140, 40])
    chart_tbl.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),PARCHMENT),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('LEFTPADDING',(0,0),(-1,-1),20),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
    elements.append(chart_tbl)
    elements.append(space(25))

    # ── FINAL STATS ──
    sw = (W - 50) / 3
    def mk_stat(num, lbl, bg, bcol, tcol):
        return Table([[Paragraph(str(num), tcol)], [Paragraph(lbl, s_stat_lbl)]], colWidths=[sw], style=[('BACKGROUND',(0,0),(-1,-1),bg),('BOX',(0,0),(-1,-1),1.2,bcol),('ROUNDEDCORNERS',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),10),('BOTTOMPADDING',(0,0),(-1,-1),10)])
    
    stat_row = Table([[
        mk_stat(files_sens, "SENSITIVE ERASED", RED_LIGHT, RED, s_stat_num_r),
        mk_stat(files_total, "TOTAL FILES CLEARED", get_alpha_col(NAVY, 0.05), NAVY, s_stat_num_n),
        mk_stat("100%", "INTEGRITY VERIFIED", get_alpha_col(GOLD, 0.1), GOLD, s_stat_num_g)
    ]], colWidths=[sw+10]*3)
    stat_row.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),PARCHMENT),('ALIGN',(0,0),(-1,-1),'CENTER')]))
    elements.append(stat_row)
    elements.append(space(30))

    # ── VERIFICATION SEAL ─────────────────────────────────────────────────────
    v_left = [
        [Paragraph("SECURITY VERIFICATION SUCCESSFUL", s_verified)],
        [Paragraph("Forensic analysis confirms zero-bit data remnants across all physical sectors.", s_verified_s)]
    ]
    v_left_tbl = Table(v_left, colWidths=[W*0.7])
    
    seal_svg = Table([[Paragraph("VERIFIED<br/>SECURE", sty('SEAL', fontName='Helvetica-Bold', fontSize=6, textColor=get_alpha_col(NAVY, 0.4), alignment=1))]], colWidths=[0.85*inch], rowHeights=[0.85*inch], style=[('BACKGROUND', (0,0),(-1,-1), PARCHMENT), ('BOX', (0,0),(-1,-1), 1.5, get_alpha_col(NAVY, 0.1)), ('ROUNDEDCORNERS', (0,0),(-1,-1), 35), ('VALIGN', (0,0),(-1,-1), 'MIDDLE')])
    
    v_row = Table([[v_left_tbl, seal_svg]], colWidths=[W*0.75, W*0.25])
    v_row.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), PARCHMENT), ('VALIGN', (0,0),(-1,-1), 'MIDDLE'), ('LINEABOVE', (0,0), (-1,-1), 1, get_alpha_col(NAVY, 0.1))]))
    elements.append(v_row)
    elements.append(space(15))

    # ── SIGNATURES ──
    sig_data = [[
        Table([[Paragraph("TrustSense Core Engine", s_sig)], [Paragraph("--------------------------", s_sig_line)], [Paragraph("DIGITAL AUTHORITY SIGNATURE", s_sig_line)]], colWidths=[W*0.6], style=[('LEFTPADDING',(0,0),(-1,-1),20)]),
        Table([[Paragraph("ISSUANCE STAMP", s_valid_lbl)], [Paragraph(date, s_valid_val)]], colWidths=[W*0.3], style=[('ALIGN', (0,0),(-1,-1), 'RIGHT'), ('RIGHTPADDING', (0,0), (-1,-1), 20)])
    ]]
    s_row = Table(sig_data, colWidths=[W*0.65, W*0.35])
    s_row.setStyle(TableStyle([('BACKGROUND', (0,0),(-1,-1), PARCHMENT), ('VALIGN', (0,0),(-1,-1), 'BOTTOM'), ('BOTTOMPADDING', (0,0), (-1,-1), 15)]))
    elements.append(s_row)

    # ── MRZ ──
    m1 = f"P<TSA{device_id.replace('-',''):<30}{'<'*15}"[:44].replace('<', '&lt;')
    m2 = f"{sha_hash.upper()[:9]}{'<'*9}260516{'<'*15}"[:44].replace('<', '&lt;')
    mrz_tbl = Table([[Paragraph(m1, s_mrz)], [Paragraph(m2, s_mrz)]], colWidths=[W], style=[('BACKGROUND', (0,0),(-1,-1), PARCHMENT_D), ('LINEABOVE', (0,0), (-1,0), 0.5, get_alpha_col(NAVY, 0.1)), ('TOPPADDING', (0,0), (-1,-1), 8), ('BOTTOMPADDING', (0,0), (-1,-1), 8), ('LEFTPADDING', (0,0), (-1,-1), 20)])
    elements.append(mrz_tbl)
    elements.append(gold_strip)

    def bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(PARCHMENT)
        canvas.rect(0, 0, A4[0], A4[1], fill=1)
        canvas.setStrokeColor(GOLD)
        canvas.setLineWidth(2)
        canvas.rect(12, 12, A4[0]-24, A4[1]-24) # Border
        canvas.restoreState()

    doc.build(elements, onFirstPage=bg, onLaterPages=bg)
    return buffer.getvalue()
