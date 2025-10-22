# quick_scan_stream.py
import sys, re, csv, os, pathlib

if len(sys.argv) < 2:
    print("Usage: python quick_scan_stream.py <full_mem.bin> [out_dir]")
    sys.exit(1)

path = sys.argv[1]
outdir = sys.argv[2] if len(sys.argv) > 2 else str(pathlib.Path(path).parent)
os.makedirs(outdir, exist_ok=True)
csv_path = os.path.join(outdir, "findings.csv")
txt_path = os.path.join(outdir, "findings.txt")

# байтовые шаблоны
keywords = [b"password", b"passwd", b"pwd", b"pin", b"secret", b"client_secret",
            b"token", b"access_token", b"refresh_token", b"api_key", b"jwt", b"bearer",
            b"private_key", b"ssh_key", b"rsa_key", b"session", b"session_id",
            b"cookie", b"app_instance_id"]
kw_re = re.compile(b"(" + b"|".join(re.escape(k) for k in keywords) + b")", re.IGNORECASE)

# JWT-like простая проверка
jwt_re = re.compile(br"[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

CHUNK = 4 * 1024 * 1024   # 4 MB
OVERLAP = 4096            # 4 KB overlap
CONTEXT = 200             # bytes context

def iter_matches(fpath):
    with open(fpath, "rb") as f:
        pos = 0
        prev = b""
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            buf = prev + block
            # ключевые слова
            for m in kw_re.finditer(buf):
                start = pos - len(prev) + m.start()
                s = buf[max(0, m.start()-CONTEXT): m.end()+CONTEXT]
                yield ("keyword", start, m.group(0).decode('utf-8','ignore'), s)
            # JWT-like
            for m in jwt_re.finditer(buf):
                start = pos - len(prev) + m.start()
                s = buf[max(0, m.start()-CONTEXT): m.end()+CONTEXT]
                yield ("jwt", start, m.group(0).decode('utf-8','ignore'), s)
            pos += len(block)
            prev = block[-OVERLAP:] if len(block) >= OVERLAP else block

def context_preview_hex(b):
    # ограничим длину hex превью
    return b.hex()[:2000]

with open(csv_path, "w", newline="", encoding="utf-8") as cf, open(txt_path, "w", encoding="utf-8") as tf:
    writer = csv.writer(cf)
    writer.writerow(["type","offset","match_preview","context_preview_hex"])
    count = 0
    for typ, offset, match_preview, context in iter_matches(path):
        writer.writerow([typ, offset, match_preview, context_preview_hex(context)])
        tf.write(f"{typ} @ {offset}\n")
        tf.write(match_preview + "\n")
        # try to show readable context
        tf.write(context.decode('utf-8','ignore') + "\n")
        tf.write("-"*80 + "\n")
        count += 1
    print("Found", count, "matches ->", csv_path, txt_path)
