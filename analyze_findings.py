#!/usr/bin/env python3
"""
analyze_findings.py

Improved/strict JWT detection:
 - only label "jwt" when header or payload decodes to JSON (header usually contains "alg"/"typ")
 - otherwise label as long_token / base64_dot_match
Usage:
 python analyze_findings_strict_jwt.py <findings.csv> <out_dir>
"""

import sys, os, csv, re, json, base64
from pathlib import Path
from collections import Counter

# ---------- helpers ----------
def clean_hex(s):
    if s is None:
        return b""
    if isinstance(s, bytes):
        s = s.decode('utf-8', errors='ignore')
    hx = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(hx) % 2 == 1:
        hx = hx[:-1]
    try:
        return bytes.fromhex(hx)
    except Exception:
        return b""

def bytes_to_text_clean(b):
    if not b:
        return ""
    try:
        chars = []
        for x in b:
            if 32 <= x <= 126 or x in (9,10,13):
                chars.append(chr(x))
            else:
                chars.append(' ')
        text = ''.join(chars)
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    except Exception:
        return ""

def extract_printables(text, minlen=4):
    return re.findall(r'[\x20-\x7E]{%d,}' % minlen, text)

def luhn_check(numstr):
    s = ''.join(ch for ch in numstr if ch.isdigit())
    if len(s) < 13 or len(s) > 19:
        return False
    total = 0
    alt = False
    for d in s[::-1]:
        n = int(d)
        if alt:
            n *= 2
            if n > 9: n -= 9
        total += n
        alt = not alt
    return total % 10 == 0

def base64url_decode_try(s):
    # s: str (base64url without padding)
    if not isinstance(s, str):
        try:
            s = s.decode('utf-8', errors='ignore')
        except:
            return None
    s = s.replace('-', '+').replace('_', '/')
    pad = (-len(s)) % 4
    if pad:
        s += '=' * pad
    try:
        return base64.b64decode(s)
    except Exception:
        return None

def decode_jwt_strict(token):
    """
    Try to decode token parts and require JSON in header or payload.
    Returns dict:
    { valid: bool, header: obj or None, payload: obj or None, reason: str }
    """
    parts = token.split('.')
    if len(parts) < 2:
        return {'valid': False, 'reason': 'not-enough-parts'}
    header_b = base64url_decode_try(parts[0])
    payload_b = base64url_decode_try(parts[1])
    header = None
    payload = None
    # try parse header JSON
    if header_b:
        try:
            header_txt = header_b.decode('utf-8', errors='ignore')
            header = json.loads(header_txt)
        except Exception:
            header = None
    # try parse payload JSON
    if payload_b:
        try:
            payload_txt = payload_b.decode('utf-8', errors='ignore')
            payload = json.loads(payload_txt)
        except Exception:
            # payload may be non-json (opaque) - keep textual fallback
            try:
                payload = payload_b.decode('utf-8', errors='ignore')
            except:
                payload = None
    # Decide validity:
    # Strong: header is JSON and contains "alg" or "typ"
    if isinstance(header, dict) and ('alg' in header or 'typ' in header):
        return {'valid': True, 'header': header, 'payload': payload, 'reason': 'header-json-with-alg'}
    # Accept if payload is JSON object (useful for JWTs without typ in header)
    if isinstance(payload, dict):
        return {'valid': True, 'header': header, 'payload': payload, 'reason': 'payload-json'}
    return {'valid': False, 'header': header, 'payload': payload, 'reason': 'no-json'}

# ---------- patterns ----------
jwt_bytes_re = re.compile(rb'[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}')
email_re = re.compile(r'[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}')
url_re = re.compile(r'https?://[^\s\'"<>]{6,200}')
bearer_re = re.compile(r'(?:Authorization[:=]\s*Bearer\s+|bearer\s+)([A-Za-z0-9\-\._~\+/]+=*)', flags=re.IGNORECASE)
token_like_re = re.compile(rb'[A-Za-z0-9_\-]{20,}')
cc_re = re.compile(r'(?:\b)(?:\d[ -]*?){13,19}\b')
phone_re = re.compile(r'(?:\+?\d{1,3}[-\s\.]?)?(?:\(?\d{2,4}\)?[-\s\.]?)?\d{6,12}')

# ---------- analyze single row ----------
def analyze_row(row_idx, row, hex_candidate):
    findings = []
    offset = None
    try:
        if len(row) >= 2:
            try:
                offset = int(row[1])
            except:
                m = re.search(r'\d{1,}', ','.join(row))
                if m:
                    offset = int(m.group(0))
    except Exception:
        offset = None

    hex_field = None
    if hex_candidate is not None and hex_candidate < len(row):
        hex_field = row[hex_candidate]
    else:
        hex_field = row[-1] if row else ''

    raw = clean_hex(hex_field)
    text = bytes_to_text_clean(raw)
    runs = extract_printables(text, minlen=4)

    # Strict JWT detection: search in raw bytes, then validate
    for m in jwt_bytes_re.finditer(raw):
        try:
            token = m.group(0).decode('utf-8', errors='ignore')
        except:
            token = str(m.group(0))
        info = decode_jwt_strict(token)
        if info.get('valid'):
            findings.append({'type':'jwt','offset':offset,'match':token,'context':text,'jwt_header':info.get('header'),'jwt_payload':info.get('payload'),'jwt_valid_json':True})
        else:
            # Not a valid JWT per stricter rules -> treat as long/base64-like token
            findings.append({'type':'base64_dot_match','offset':offset,'match':token,'context':text,'jwt_valid_json':False,'jwt_reason':info.get('reason')})

    # emails
    for m in email_re.finditer(text):
        findings.append({'type':'email','offset':offset,'match':m.group(0),'context':text})

    # urls
    for m in url_re.finditer(text):
        findings.append({'type':'url','offset':offset,'match':m.group(0),'context':text})

    # bearer tokens (text)
    for m in bearer_re.finditer(text):
        findings.append({'type':'bearer','offset':offset,'match':m.group(1),'context':text})

    # possible credit-card sequences
    for m in cc_re.finditer(text):
        s = re.sub(r'[^0-9]', '', m.group(0))
        ok = luhn_check(s)
        findings.append({'type':'possible_card','offset':offset,'match':s,'context':text,'luhn':ok})

    # phone-like
    for m in phone_re.finditer(text):
        findings.append({'type':'phone','offset':offset,'match':m.group(0),'context':text})

    # long base64-like tokens in raw bytes (not dot-separated)
    for m in token_like_re.finditer(raw):
        token = m.group(0)
        if len(token) >= 20:
            try:
                tok_text = token.decode('utf-8', errors='ignore')
            except:
                tok_text = str(token)
            findings.append({'type':'long_token','offset':offset,'match':tok_text,'context':text})

    # printable runs as low-priority strings
    for r in runs:
        findings.append({'type':'string_run','offset':offset,'match':r,'context':text})

    return findings

# ---------- main ----------
def main():
    if len(sys.argv) < 3:
        print("Usage: python analyze_findings_strict_jwt.py <findings.csv> <out_dir>")
        sys.exit(1)
    csv_path = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    with csv_path.open('r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        for r in reader:
            if not any(cell.strip() for cell in r):
                continue
            rows.append(r)

    hex_col = None
    if rows:
        sample = rows[:min(10, len(rows))]
        col_scores = {}
        for r in sample:
            for i, cell in enumerate(r):
                cleaned = re.sub(r'[^0-9a-fA-F]', '', cell)
                if len(cleaned) >= 40:
                    col_scores[i] = col_scores.get(i,0) + 1
        if col_scores:
            hex_col = max(col_scores.items(), key=lambda x: x[1])[0]
        else:
            hex_col = len(rows[0]) - 1

    all_findings = []
    summary = Counter()
    for idx, row in enumerate(rows):
        fnds = analyze_row(idx, row, hex_col)
        for f in fnds:
            f['row_index'] = idx
            f['raw_row'] = row
            all_findings.append(f)
            summary[f['type']] += 1

    out_csv = out_dir / "findings_decoded.csv"
    with out_csv.open('w', newline='', encoding='utf-8') as outf:
        writer = csv.writer(outf)
        writer.writerow(['row_index','type','offset','match','luhn_valid','context_preview','jwt_valid_json','jwt_header','jwt_payload','note'])
        for f in all_findings:
            context_preview = f.get('context','')
            if context_preview:
                context_preview = re.sub(r'[^ -~]+', ' ', context_preview)[:1000]
            writer.writerow([
                f.get('row_index'),
                f.get('type'),
                f.get('offset'),
                f.get('match'),
                f.get('luhn',''),
                context_preview,
                bool(f.get('jwt_valid_json', False)),
                json.dumps(f.get('jwt_header')) if f.get('jwt_header') is not None else '',
                json.dumps(f.get('jwt_payload')) if f.get('jwt_payload') is not None else '',
                f.get('jwt_reason','') if f.get('jwt_reason') else ''
            ])

    out_summary = out_dir / "findings_summary.txt"
    with out_summary.open('w', encoding='utf-8') as s:
        s.write("Findings summary (strict JWT)\n")
        s.write("=============================\n\n")
        total = sum(summary.values())
        s.write(f"Total findings: {total}\n\n")
        for k,v in summary.most_common():
            s.write(f"{k}: {v}\n")
        s.write("\nTop examples:\n\n")
        for f in all_findings[:200]:
            s.write(f"{f.get('type')} @ row {f.get('row_index')} offset {f.get('offset')} -> {f.get('match')}\n")
            ctxt = f.get('context','')
            if ctxt:
                ctxt = re.sub(r'[^ -~]+', ' ', ctxt)
                s.write(ctxt[:400] + "\n")
            if f.get('type') == 'jwt' and f.get('jwt_payload') is not None:
                s.write("JWT payload: " + json.dumps(f.get('jwt_payload')) + "\n")
            s.write("-"*60 + "\n")

    print("Done.")
    print("Detailed CSV:", out_csv)
    print("Summary:", out_summary)

if __name__ == '__main__':
    main()
