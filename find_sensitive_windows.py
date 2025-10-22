# -*- coding: utf-8 -*-
"""
Поиск чувствительных данных.
Классификация: MASVS-STORAGE (High / Medium / Low)
"""

import os, re, csv, sys, argparse
from collections import defaultdict

# ---------------- аргументы ----------------
ap = argparse.ArgumentParser(description="Scan folder for sensitive keys (MASVS-STORAGE).")
ap.add_argument("folder", help="Folder to scan")
ap.add_argument("output", nargs="?", default="sensitive_output", help="Output folder")
ap.add_argument("--max-size", type=float, default=5.0, help="Max text file size in MB (default 5 MB)")
ap.add_argument("--scan-binaries", action="store_true", help="Also scan binary files via strings-like extraction")
ap.add_argument("--progress", type=int, default=200, help="Show progress every N files")
args = ap.parse_args()

FOLDER = args.folder
OUTPUT_DIR = args.output
MAX_SIZE = int(args.max_size * 1024 * 1024)
SCAN_BINARIES = args.scan_binaries
PROGRESS_EVERY = max(1, args.progress)

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------- ключи ----------------
HIGH = [
    "password","passwd","pwd","pin","secret","client_secret","token","access_token",
    "refresh_token","api_key","jwt","bearer","private_key","ssh_key","rsa_key",
    "session","session_id","cookie","app_instance_id"
]
MEDIUM = [
    "user","username","userid","user_id","idfa","gaid","advertising_id",
    "email","phone","phone_number"
]
LOW = [
    "ssn","dob","birth","credit","card","iban","location","lat","lon",
    "coordinates","origin","visit","history","url","hostname"
]
ALL_KEYS = HIGH + MEDIUM + LOW
pattern = re.compile(r'\b(' + '|'.join(map(re.escape, ALL_KEYS)) + r')\b\s*([:=\(])\s*(.*)', re.I)

# ---------------- бинарные расширения ----------------
binary_ext = (".png",".jpg",".jpeg",".gif",".webp",".so",".dex",".jar",".apk",".zip",
              ".7z",".bin",".db",".sqlite",".mp3",".mp4",".avi",".pdf",".dll",".exe",
              ".dat",".pack",".woff",".ttf",".smali")

def is_binary(path):
    try:
        if path.lower().endswith(binary_ext):
            return True
        with open(path,"rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return True
    except Exception:
        return True
    return False

def extract_strings(path, min_len=4):
    out=[]; seq=bytearray()
    try:
        with open(path,"rb") as f:data=f.read()
    except Exception:return out
    for b in data:
        if 32<=b<=126:
            seq.append(b)
        else:
            if len(seq)>=min_len:
                out.append(seq.decode("ascii","ignore"))
            seq=bytearray()
    if len(seq)>=min_len:
        out.append(seq.decode("ascii","ignore"))
    return out

def read_text_lines(path):
    try:
        with open(path,"rb") as f:raw=f.read()
    except Exception:return []
    for enc in ("utf-8","utf-16","cp1251","latin-1"):
        try:
            return raw.decode(enc,errors="ignore").splitlines()
        except Exception:
            continue
    return []

# ---------------- подготовка файлов вывода ----------------
files_out = {
    "High": os.path.join(OUTPUT_DIR, "high.csv"),
    "Medium": os.path.join(OUTPUT_DIR, "medium.csv"),
    "Low": os.path.join(OUTPUT_DIR, "low.csv"),
}
writers = {}
for lvl, path in files_out.items():
    f = open(path,"w",newline="",encoding="utf-8")
    w = csv.writer(f)
    w.writerow(["File","LineNumber","Key","Value","Line"])
    writers[lvl]=(w,f)

counts={"High":0,"Medium":0,"Low":0}
files_seen={"High":set(),"Medium":set(),"Low":set()}

# ---------------- основной проход ----------------
processed=0
for root,dirs,files in os.walk(FOLDER):
    for name in files:
        path=os.path.join(root,name)
        processed+=1
        if processed % PROGRESS_EVERY == 0:
            # вывод прогресса в одной строке
            print(f"Processed: {processed} files... {path[:70]}", end='\r', flush=True)
        try:size=os.path.getsize(path)
        except Exception:continue

        if not SCAN_BINARIES and (size>MAX_SIZE or is_binary(path)):
            continue

        lines=[]
        if SCAN_BINARIES and is_binary(path):
            lines=extract_strings(path)
        else:
            lines=read_text_lines(path)

        for i,line in enumerate(lines,1):
            m=pattern.search(line)
            if not m:continue
            key,value=m.group(1),m.group(3).strip()
            key_l=key.lower()
            if key_l in [k.lower() for k in HIGH]:lvl="High"
            elif key_l in [k.lower() for k in MEDIUM]:lvl="Medium"
            else:lvl="Low"
            writers[lvl][0].writerow([path,i,key,value,line.strip()])
            counts[lvl]+=1
            files_seen[lvl].add(path)

# ---------------- закрытие файлов ----------------
for w,f in writers.values():f.close()

# ---------------- вывод ----------------
print("\n\nDone! Results saved in folder:", OUTPUT_DIR)
print("Files: high.csv, medium.csv, low.csv\n")

# подробный отчет с топ-ключами
for lvl in ("High","Medium","Low"):
    print(f"{lvl}: {counts[lvl]} matches in {len(files_seen[lvl])} files")
    if files_seen[lvl]:
        files_list = list(files_seen[lvl])
        print("Files:", ", ".join(files_list[:5]) + ("..." if len(files_list) > 5 else ""))
    # подсчет частоты ключей
    key_freq = defaultdict(int)
    csv_file = os.path.join(OUTPUT_DIR, f"{lvl.lower()}.csv")
    try:
        with open(csv_file,"r",encoding="utf-8") as f:
            next(f)  # пропустить заголовок
            for row in csv.reader(f):
                key_freq[row[2]] += 1
    except Exception:
        pass
    if key_freq:
        print("Key frequency:")
        for k, v in sorted(key_freq.items(), key=lambda x: x[1], reverse=True):
            print(f"  {k}: {v}")
    print()
