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


# ── Palette ────────────────────────────────────────────────────────────────────
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

# Accent bar colors matching the on-screen chart
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
    Generates the navy/gold official passport PDF — matching the on-screen passport exactly.
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
    risk_br      = data.get('risk_breakdown', {})
    ai_reason    = data.get('ai_reason', '')

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36
    )

    # ── Styles ─────────────────────────────────────────────────────────────────
    def sty(name, **kw):
        return ParagraphStyle(name, **kw)

    s_tiny_gold  = sty('TG',  fontName='Courier-Bold',  fontSize=7,  textColor=GOLD,       leading=10, alignment=0)
    s_title      = sty('TT',  fontName='Helvetica-Bold', fontSize=20, textColor=WHITE,      leading=24, alignment=0)
    s_sub        = sty('TS',  fontName='Courier-Bold',  fontSize=8,  textColor=GOLD,       leading=11, alignment=0)
    s_doc_no_lbl = sty('DL',  fontName='Courier-Bold',  fontSize=7,  textColor=GOLD,       leading=9,  alignment=2)
    s_doc_no_val = sty('DV',  fontName='Courier-Bold',  fontSize=11, textColor=GOLD,       leading=13, alignment=2)
    
    s_field_lbl  = sty('FL',  fontName='Helvetica-Bold',fontSize=7,  textColor=GRAY,       leading=9,  alignment=0)
    s_field_val  = sty('FV',  fontName='Helvetica-Bold',fontSize=12, textColor=NAVY,       leading=15, alignment=0)
    
    s_stat_num_r = sty('SNR', fontName='Helvetica-Bold',fontSize=28, textColor=RED,        leading=32, alignment=1)
    s_stat_num_n = sty('SNN', fontName='Helvetica-Bold',fontSize=28, textColor=NAVY,       leading=32, alignment=1)
    s_stat_num_g = sty('SNG', fontName='Helvetica-Bold',fontSize=28, textColor=colors.HexColor("#9a7a2a"), leading=32, alignment=1)
    
    s_stat_lbl_r = sty('SLR', fontName='Helvetica-Bold',fontSize=7,  textColor=RED,        leading=9,  alignment=1)
    s_stat_lbl_n = sty('SLN', fontName='Helvetica-Bold',fontSize=7,  textColor=GRAY,       leading=9,  alignment=1)
    s_stat_lbl_g = sty('SLG', fontName='Helvetica-Bold',fontSize=7,  textColor=colors.HexColor("#9a7a2a"), leading=9,  alignment=1)
    
    s_chart_lbl  = sty('CL',  fontName='Helvetica-Bold',fontSize=7,  textColor=GRAY_LIGHT, leading=9,  alignment=0)
    s_bar_ext    = sty('BE',  fontName='Courier-Bold',  fontSize=6,  textColor=GRAY,       leading=8,  alignment=1)
    s_bar_cnt    = sty('BC',  fontName='Courier',       fontSize=6,  textColor=GRAY_LIGHT, leading=8,  alignment=1)
    
    s_verified   = sty('VF',  fontName='Helvetica-Bold',fontSize=11, textColor=GREEN,      leading=14, alignment=0)
    s_verified_s = sty('VS',  fontName='Helvetica',     fontSize=7,  textColor=GRAY,       leading=10, alignment=0)
    
    s_sig        = sty('SG',  fontName='Times-Italic',  fontSize=12, textColor=GRAY_LIGHT, leading=16, alignment=0)
    s_sig_line   = sty('SGL', fontName='Courier-Bold',  fontSize=7,  textColor=GRAY_LIGHT, leading=9,  alignment=0)
    
    s_valid_lbl  = sty('VL',  fontName='Courier-Bold',  fontSize=7,  textColor=GRAY_LIGHT, leading=9,  alignment=2)
    s_valid_val  = sty('VV',  fontName='Helvetica-Bold',fontSize=11, textColor=NAVY,       leading=13, alignment=2)
    
    s_mrz        = sty('MZ',  fontName='Courier',       fontSize=7,  textColor=colors.HexColor("#9ca3af"), leading=10, alignment=0)

    W = doc.width
    elements = []

    # ── GOLD TOP STRIP ────────────────────────────────────────────────────────
    gold_strip = Table([['']], colWidths=[W])
    gold_strip.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), GOLD),
        ('TOPPADDING',(0,0),(-1,-1),3),
        ('BOTTOMPADDING',(0,0),(-1,-1),3)
    ]))
    elements.append(gold_strip)

    # ── DARK NAVY HEADER ──────────────────────────────────────────────────────
    emblem_circle = Table([['✦']], colWidths=[0.45*inch], rowHeights=[0.45*inch])
    emblem_circle.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), colors.rgba(GOLD.red, GOLD.green, GOLD.blue, 0.1)),
        ('BOX', (0,0),(-1,-1), 1.5, colors.rgba(GOLD.red, GOLD.green, GOLD.blue, 0.7)),
        ('ROUNDEDCORNERS', (0,0),(-1,-1), 16),
        ('ALIGN', (0,0),(-1,-1), 'CENTER'),
        ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ('TEXTCOLOR', (0,0),(-1,-1), GOLD),
        ('FONTNAME', (0,0),(-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0),(-1,-1), 16)
    ]))

    title_block = [
        [Paragraph("OFFICIAL DOCUMENT", s_tiny_gold)],
        [Paragraph("Data Sanitization Passport", s_title)],
        [Paragraph("TRUSTSENSE FORENSIC AUTHORITY", s_sub)],
    ]
    title_tbl = Table(title_block, colWidths=[W*0.6])
    title_tbl.setStyle(TableStyle([
        ('TOPPADDING',(0,0),(-1,-1),0),
        ('BOTTOMPADDING',(0,0),(-1,-1),0),
        ('LEFTPADDING',(0,0),(-1,-1),0)
    ]))

    doc_no_block = [
        [Paragraph("DOCUMENT NO.", s_doc_no_lbl)],
        [Paragraph(sha_hash[:12].upper(), s_doc_no_val)],
    ]
    doc_no_tbl = Table(doc_no_block, colWidths=[W*0.25])
    doc_no_tbl.setStyle(TableStyle([('ALIGN', (0,0),(-1,-1), 'RIGHT')]))

    header_row = [[emblem_circle, title_tbl, doc_no_tbl]]
    header_tbl = Table(header_row, colWidths=[0.6*inch, W*0.6, W*0.28])
    header_tbl.setStyle(TableStyle([
        ('VALIGN',  (0,0),(-1,-1), 'MIDDLE'),
        ('BACKGROUND',(0,0),(-1,-1), colors.HexColor("#0f1c3a")),
        ('TOPPADDING',(0,0),(-1,-1),18),
        ('BOTTOMPADDING',(0,0),(-1,-1),18),
        ('LEFTPADDING',(0,0),(-1,-1),15),
        ('RIGHTPADDING',(0,0),(-1,-1),15),
    ]))
    elements.append(header_tbl)

    # ── GOLD-NAVY-GOLD DIVIDER ────────────────────────────────────────────────
    div = Table([['']], colWidths=[W])
    div.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),GOLD),('TOPPADDING',(0,0),(-1,-1),3),('BOTTOMPADDING',(0,0),(-1,-1),3)]))
    elements.append(div)

    # ── PARCHMENT BODY ────────────────────────────────────────────────────────
    def parchment_row(cells, col_widths, row_h=None, styles=None):
        t = Table([cells], colWidths=col_widths, rowHeights=row_h)
        if styles: t.setStyle(TableStyle(styles))
        return t

    elements.append(parchment_row([''], [W], [12], [('BACKGROUND', (0,0),(-1,-1), PARCHMENT)]))

    # ── CREDENTIAL FIELDS ────────────────────────────────────────────────────
    cw = W / 4
    fields = [
        [Paragraph("HOLDER / NODE", s_field_lbl), Paragraph("DATE OF ISSUE", s_field_lbl), Paragraph("PROTOCOL APPLIED", s_field_lbl), Paragraph("INTEGRITY RATING", s_field_lbl)],
        [Paragraph(device_id, s_field_val), Paragraph(date, s_field_val), Paragraph(protocol, s_field_val), Paragraph(f"{trust_score}%", s_field_val)]
    ]
    cred_tbl = Table(fields, colWidths=[cw]*4)
    cred_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), PARCHMENT),
        ('LINEBELOW', (0,1), (-1,1), 1.5, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.2)),
        ('TOPPADDING', (0,0),(-1,-1), 4),
        ('BOTTOMPADDING', (0,0),(-1,-1), 12),
        ('LEFTPADDING', (0,0),(-1,-1), 15),
    ]))
    elements.append(cred_tbl)
    elements.append(parchment_row([''], [W], [15], [('BACKGROUND', (0,0),(-1,-1), PARCHMENT)]))

    # ── STATS ROW ────────────────────────────────────────────────────────────
    sw = (W - 40) / 3
    s1 = Table([[Paragraph(str(files_sens), s_stat_num_r)], [Paragraph("THREATS PURGED", s_stat_lbl_r)]], colWidths=[sw])
    s1.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),RED_LIGHT),('BOX',(0,0),(-1,-1),1.5,colors.HexColor("#fecaca")),('ROUNDEDCORNERS',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
    
    s2 = Table([[Paragraph(str(files_total), s_stat_num_n)], [Paragraph("FILES CLEARED", s_stat_lbl_n)]], colWidths=[sw])
    s2.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.05)),('BOX',(0,0),(-1,-1),1.5,colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.1)),('ROUNDEDCORNERS',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
    
    s3 = Table([[Paragraph("100%", s_stat_num_g)], [Paragraph("VERIFIED CLEAN", s_stat_lbl_g)]], colWidths=[sw])
    s3.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),colors.rgba(GOLD.red, GOLD.green, GOLD.blue, 0.1)),('BOX',(0,0),(-1,-1),1.5,colors.rgba(GOLD.red, GOLD.green, GOLD.blue, 0.3)),('ROUNDEDCORNERS',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8)]))
    
    stat_row = Table([[s1, s2, s3]], colWidths=[sw+10]*3)
    stat_row.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,-1),PARCHMENT),('ALIGN',(0,0),(-1,-1),'CENTER'),('LEFTPADDING',(0,0),(-1,-1),10)]))
    elements.append(stat_row)
    elements.append(parchment_row([''], [W], [15], [('BACKGROUND', (0,0),(-1,-1), PARCHMENT)]))

    # ── FILE TYPE BAR CHART ───────────────────────────────────────────────────
    if file_types:
        elements.append(parchment_row([Paragraph("ERADICATED FILE DISTRIBUTION", s_chart_lbl)], [W], [10], [('BACKGROUND', (0,0),(-1,-1), PARCHMENT), ('LEFTPADDING', (0,0),(-1,-1), 15)]))
        
        entries = list(file_types.items())[:8]
        max_f   = max(file_types.values()) if file_types else 1
        total_f = sum(file_types.values())
        bar_w   = (W - 30) / max(len(entries), 1)
        
        # Labels and bars
        bar_cells = []
        for i, (ext, cnt) in enumerate(entries):
            col = CHART_COLS[i % len(CHART_COLS)]
            h   = max(3, int((cnt / max_f) * 45))
            
            # Sub-table for each bar column
            bar_col = Table([
                [Paragraph(str(cnt), s_bar_cnt)],
                [Table([['']], colWidths=[bar_w-6], rowHeights=[h], style=[('BACKGROUND',(0,0),(-1,-1),col),('ROUNDEDCORNERS',(0,0),(-1,-1),2)])],
                [Paragraph(f".{ext}", s_bar_ext)]
            ], colWidths=[bar_w])
            bar_col.setStyle(TableStyle([
                ('ALIGN', (0,0),(-1,-1), 'CENTER'),
                ('VALIGN', (0,1), (0,1), 'BOTTOM'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 0),
                ('TOPPADDING', (0,0), (-1,-1), 0),
            ]))
            bar_cells.append(bar_col)
            
        chart_tbl = Table([bar_cells], colWidths=[bar_w]*len(entries))
        chart_tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(-1,-1), PARCHMENT),
            ('ALIGN', (0,0),(-1,-1), 'CENTER'),
            ('VALIGN', (0,0),(-1,-1), 'BOTTOM'),
            ('LINEBELOW', (0,0), (-1,0), 0.5, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.15)),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10)
        ]))
        elements.append(chart_tbl)
        elements.append(parchment_row([''], [W], [15], [('BACKGROUND', (0,0),(-1,-1), PARCHMENT)]))

    # ── VERIFICATION + SEAL ───────────────────────────────────────────────────
    v_left = [
        [Paragraph("✓  Sanitization Verified", s_verified)],
        [Paragraph("All sectors overwritten — confirmed irrecoverable", s_verified_s)]
    ]
    v_left_tbl = Table(v_left, colWidths=[W*0.7])
    v_left_tbl.setStyle(TableStyle([('LEFTPADDING',(0,0),(-1,-1),15),('TOPPADDING',(0,0),(-1,-1),0)]))

    seal_svg = Table([[Paragraph("VERIFIED<br/>SECURE", sty('SEAL', fontName='Helvetica-Bold', fontSize=5, textColor=colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.5), leading=6, alignment=1))]], colWidths=[0.8*inch], rowHeights=[0.8*inch])
    seal_svg.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), PARCHMENT),
        ('BOX', (0,0),(-1,-1), 1, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.2)),
        ('ROUNDEDCORNERS', (0,0),(-1,-1), 30),
        ('ALIGN', (0,0),(-1,-1), 'CENTER'),
        ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ('LINEBELOW', (0,0),(-1,-1), 0.5, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.1), None, (2,2)) # dash
    ]))

    v_row = Table([[v_left_tbl, seal_svg]], colWidths=[W*0.75, W*0.25])
    v_row.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), PARCHMENT),
        ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
        ('RIGHTPADDING', (0,0), (-1,-1), 15),
        ('LINEABOVE', (0,0), (-1,-1), 1, colors.rgba(NAVY.red, NAVY.green, NAVY.blue, 0.1))
    ]))
    elements.append(v_row)
    elements.append(parchment_row([''], [W], [10], [('BACKGROUND', (0,0),(-1,-1), PARCHMENT)]))

    # ── SIGNATURE ────────────────────────────────────────────────────────────
    sig_block = [
        [Paragraph("TrustSense Engine", s_sig)],
        [Paragraph("──────────────────────────", s_sig_line)],
        [Paragraph("AUTHORIZED SIGNATURE", s_sig_line)]
    ]
    sig_tbl = Table(sig_block, colWidths=[W*0.6])
    sig_tbl.setStyle(TableStyle([('LEFTPADDING',(0,0),(-1,-1),15),('TOPPADDING',(0,0),(-1,-1),2)]))

    valid_block = [
        [Paragraph("VALID FROM", s_valid_lbl)],
        [Paragraph(date, s_valid_val)],
    ]
    valid_tbl = Table(valid_block, colWidths=[W*0.35])
    valid_tbl.setStyle(TableStyle([('ALIGN', (0,0),(-1,-1), 'RIGHT'), ('RIGHTPADDING', (0,0), (-1,-1), 15)]))

    sig_row = Table([[sig_tbl, valid_tbl]], colWidths=[W*0.65, W*0.35])
    sig_row.setStyle(TableStyle([
        ('BACKGROUND', (0,0),(-1,-1), PARCHMENT),
        ('VALIGN', (0,0),(-1,-1), 'BOTTOM'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12)
    ]))
    elements.append(sig_row)

    # ── MRZ (MACHINE READABLE ZONE) ──────────────────────────────────────────
    mrz_raw1 = f"P<TSA{device_id.replace('-',''):<30}{'<'*15}"[:44]
    mrz_raw2 = f"{sha_hash.upper()[:9]}{'<'*9}260516{'<'*15}"[:44]
    
    mrz1 = mrz_raw1.replace('<', '&lt;')
    mrz2 = mrz_raw2.replace('<', '&lt;')
    mrz_tbl = Table([
        [Paragraph(mrz1, s_mrz)],
        [Paragraph(mrz2, s_mrz)],
    ], colWidths=[W])
    mrz_tbl.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,-1),PARCHMENT_D),
        ('LINEABOVE',(0,0),(-1,0),0.5,colors.HexColor("#d1d5db")),
        ('TOPPADDING',(0,0),(-1,-1),6),('BOTTOMPADDING',(0,0),(-1,-1),6),
        ('LEFTPADDING',(0,0),(-1,-1),12),('RIGHTPADDING',(0,0),(-1,-1),12),
    ]))
    elements.append(mrz_tbl)
    elements.append(gold_strip)

    # ── PAGE BACKGROUND ───────────────────────────────────────────────────────
    def add_background(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(PARCHMENT)
        canvas.rect(0, 0, A4[0], A4[1], fill=1)
        # Subtle gold border
        canvas.setStrokeColor(GOLD)
        canvas.setLineWidth(1.5)
        canvas.rect(10, 10, A4[0]-20, A4[1]-20)
        canvas.restoreState()

    doc.build(elements, onFirstPage=add_background, onLaterPages=add_background)
    return buffer.getvalue()
