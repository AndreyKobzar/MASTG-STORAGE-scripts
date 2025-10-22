#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mastg_logs_auto.py
Обновлённая версия с frida-python API (auto-fallback to CLI background)
и улучшенной статической фильтрацией/приоритизацией.

Добавлено:
- фильтр логов (Log.d / Log.i / Log.e / Logger / Timber / Throwable / Exception);
- счётчик найденных совпадений по приоритету (High/Medium/Low);
- весь остальной функционал оставлен без изменений.
"""

from __future__ import annotations
import os
import re
import subprocess
import sys
import time
import shutil
import tempfile
import csv
import json
from pathlib import Path
from typing import Optional, Tuple, List, Dict

# ========== USER CONFIG ==========
APP_PACKAGE = "ru.x5.sphere"
APK_PATH = r"...\<your.apk>"
JADX_PATH = r"...\bin\jadx.bat"
FRIDA_SCRIPT_PATH = r"...\log_hook.js"
OUTPUT_DIR = Path("analysis_results")
OUTPUT_DIR.mkdir(exist_ok=True)
# =================================

# Filenames
STATIC_FULL = OUTPUT_DIR / "static_findings_full.csv"
STATIC_SUMMARY = OUTPUT_DIR / "static_findings_summary.csv"
DYNAMIC_LOG = OUTPUT_DIR / "results_dynamic.csv"
NATIVE_CSV = OUTPUT_DIR / "native_findings.csv"
FRIDA_API_POC_FILE = OUTPUT_DIR / "frida_api_poc.jsonl"
FRIDA_CLI_LOG = OUTPUT_DIR / "frida_session.log"

# Sensitive patterns and priority mapping
KEYWORDS = [
    "password", "passwd", "pwd", "token", "auth", "secret", "bearer", "jwt",
    "sessionid", "set-cookie", "cookie", "apikey", "authorization", "pin", "otp",
    "card", "cvv", "email", "phone"
]
LOG_CALL_PATTERNS = ["Log.", "System.out", "println", "Timber.", "__android_log_print", "Logger", "Throwable", "Exception", "StackTraceElement"]

PATTERNS = {
    "token_like": re.compile(r"(?i)(access_token|refresh_token|bearer\s+[A-Za-z0-9\-\._~\+/]+=*|token=|\"token\"\s*:\s*\"[^\"]+\")"),
    "password_like": re.compile(r"(?i)\b(password|passwd|pwd|pin|otp|passphrase)\b"),
    "logging_calls": re.compile(r"\b(Log\.d|Log\.i|Log\.e|Log\.v|Log\.w|System\.out\.println|Timber\.|Logger|Throwable|Exception|StackTraceElement)"),
    "url_token_param": re.compile(r"(?i)[\?&](token|access_token|password|passwd)=\S+"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "card_like": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "sentry_crash": re.compile(r"(?i)(crashlytics|sentry|fabric|firebase-crashlytics)"),
}

# ========== Utilities ==========
def run_cmd(cmd, capture_output=True, check=False, shell=False):
    try:
        sp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check, shell=shell)
        return sp.stdout.strip(), sp.stderr.strip()
    except subprocess.CalledProcessError as e:
        return e.stdout or "", e.stderr or str(e)
    except Exception as e:
        return "", str(e)

def extract_strings(file_path: Path, min_len: int = 4) -> List[str]:
    out = []
    try:
        b = file_path.read_bytes()
    except Exception:
        return out
    for m in re.findall(rb"[\x20-\x7E]{%d,}" % min_len, b):
        try:
            out.append(m.decode("utf-8", "ignore"))
        except Exception:
            pass
    return out

# ========== JADX helpers ==========
def is_gui_executable(path_str: str) -> bool:
    try:
        return "jadx-gui" in Path(path_str).name.lower()
    except Exception:
        return False

def find_cli_near_gui(gui_path: str) -> Optional[str]:
    p = Path(gui_path)
    for cand in [
        p.parent / "jadx.exe", p.parent / "jadx.bat",
        p.parent / "jadx", p.parent / "bin" / "jadx.exe",
        p.parent.parent / "bin" / "jadx.exe"
    ]:
        if cand.exists():
            return str(cand)
    return None

def find_jadx_cli() -> Optional[str]:
    if JADX_PATH:
        p = Path(JADX_PATH)
        if p.exists():
            if is_gui_executable(str(p)):
                cli = find_cli_near_gui(str(p))
                if cli:
                    return cli
            else:
                return str(p)
    for name in ("jadx", "jadx.exe", "jadx.bat"):
        path = shutil.which(name)
        if path:
            return path
    return None

def decompile_with_jadx(apk_path: str, out_dir: Path) -> Tuple[bool, str]:
    cli = find_jadx_cli()
    if not cli:
        return False, "jadx CLI not found."
    cmd = [cli, "-d", str(out_dir), apk_path]
    print("[*] Running JADX CLI:", " ".join(cmd))
    out, err = run_cmd(cmd)
    if any(out_dir.rglob("*.java")):
        return True, ""
    return False, f"jadx ran but no output. {out[:150]} {err[:150]}"

# ========== STATIC ANALYSIS (enhanced) ==========
def score_and_label(pattern_key: str, snippet: str) -> Tuple[str, int]:
    key = pattern_key.lower()
    if any(k in key for k in ("token", "password", "card", "auth", "cookie")):
        return "High", 3
    if any(k in key for k in ("logging_calls", "email", "sentry")):
        return "Medium", 2
    return "Low", 1

def static_analysis_apk(apk_path: str) -> Optional[Path]:
    print("[*] Starting static analysis...")
    out_dir = OUTPUT_DIR / "jadx_out"
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    ok, msg = decompile_with_jadx(apk_path, out_dir)
    if not ok:
        print(f"[!] JADX issue: {msg}")

    patterns = PATTERNS
    seen = set()
    full_rows = []

    for p in out_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in (".java", ".smali", ".xml"):
            try:
                text = p.read_text(errors="ignore")
            except Exception:
                continue

            # --- Основной фильтр ---
            for key, regex in patterns.items():
                for m in regex.finditer(text):
                    snippet = text[max(0, m.start() - 80): m.end() + 80].replace("\n", "\\n")
                    uid = (str(p), key, snippet[:120])
                    if uid in seen:
                        continue
                    seen.add(uid)
                    label, score = score_and_label(key, snippet)
                    # фильтр по условиям задачи
                    if key == "logging_calls" or any(k in snippet.lower() for k in KEYWORDS):
                        full_rows.append({
                            "file": str(p), "pattern": key, "match": m.group(0),
                            "snippet": snippet[:400], "priority": label, "score": score
                        })

    # подсчёт по категориям
    counts = {"High": 0, "Medium": 0, "Low": 0}
    for r in full_rows:
        counts[r["priority"]] += 1

    # сортировка
    full_rows_sorted = sorted(full_rows, key=lambda r: -r["score"])

    # запись CSV
    with STATIC_FULL.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["priority", "score", "file", "pattern", "match", "snippet"])
        writer.writeheader()
        writer.writerows(full_rows_sorted)

    with STATIC_SUMMARY.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["priority", "score", "file", "pattern", "match", "snippet"])
        writer.writeheader()
        writer.writerows(full_rows_sorted[:300])

    print(f"[+] Static analysis done. {len(full_rows_sorted)} filtered findings saved.")
    print(f"    Breakdown: High={counts['High']} | Medium={counts['Medium']} | Low={counts['Low']}")
    return STATIC_SUMMARY

# ========== DYNAMIC LOGCAT (unchanged) ==========
def monitor_logcat(package_name: str, duration: int = 60) -> Optional[Path]:
    print("[*] Starting dynamic logcat monitoring...")
    output_file = DYNAMIC_LOG
    run_cmd(["adb", "logcat", "-c"], capture_output=False)
    proc = subprocess.Popen(["adb", "logcat", "-v", "threadtime"], stdout=subprocess.PIPE, text=True)
    start_time = time.time()
    sensitive_re = re.compile(r"(?i)(password|token|auth|session|secret|apikey|access_token|refresh_token)")
    parsed = []
    with open(output_file, "w", encoding="utf-8", newline="") as cf:
        writer = csv.writer(cf)
        writer.writerow(["timestamp", "pid", "tid", "level", "tag", "message"])
        try:
            while time.time() - start_time < duration:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                # best-effort parse: threadtime format -> "YYYY-MM-DD HH:MM:SS.mmm PID TID LEVEL TAG: msg"
                # We'll not rely on exact split; just check pattern
                if sensitive_re.search(line):
                    writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), "", "", "", "", line.strip()])
            # end while
        except KeyboardInterrupt:
            pass
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                pass
    print(f"[+] Dynamic logcat monitoring complete. Log saved to {output_file}")
    return output_file

# ========== NATIVE (.so) analysis (unchanged) ==========
def analyze_native_libs(apk_path: str) -> Optional[Path]:
    print("[*] Analyzing native libraries...")
    tmp_dir = Path(tempfile.mkdtemp())
    if shutil.which("7z"):
        cmd = ["7z", "x", apk_path, f"-o{str(tmp_dir)}"]
        run_cmd(cmd, capture_output=True)
    elif shutil.which("unzip"):
        cmd = ["unzip", "-q", apk_path, "-d", str(tmp_dir)]
        run_cmd(cmd, capture_output=True)
    else:
        print("[!] Neither 7z nor unzip found - skipping native libs extraction.")
        return None

    so_files = list(tmp_dir.rglob("*.so"))
    results = []
    for so in so_files:
        for s in extract_strings(so):
            if re.search(r"(token|password|auth|key|secret|__android_log_print)", s, re.IGNORECASE):
                results.append({"file": str(so), "string": s})
    with NATIVE_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["file", "string"])
        writer.writeheader()
        writer.writerows(results)
    print(f"[+] Native libs analysis done. {len(results)} findings saved to {NATIVE_CSV}")
    return NATIVE_CSV

# ========== FRIDA API integration (auto-fallback) ==========
def _adb_get_pid(package_name: str) -> str:
    out, err = run_cmd(["adb", "shell", "pidof", package_name], capture_output=True)
    pid = out.strip().split()[0] if out.strip() else ""
    return pid

def _ensure_frida_module():
    try:
        import frida  # type: ignore
        return frida
    except Exception:
        return None

def _on_message_factory():
    def on_message(message, data):
        try:
            mtype = message.get("type")
            if mtype == "send":
                payload = message.get("payload")
                line = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "type": "send", "payload": payload}
                print("[FRIDA SEND]", payload)
                try:
                    with FRIDA_API_POC_FILE.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps(line, ensure_ascii=False) + "\n")
                except Exception:
                    pass
            elif mtype == "error":
                print("[FRIDA ERROR]", message)
                try:
                    with FRIDA_API_POC_FILE.open("a", encoding="utf-8") as fh:
                        fh.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "type": "error", "payload": message}, ensure_ascii=False) + "\n")
                except Exception:
                    pass
            else:
                print("[FRIDA MSG]", message)
        except Exception as e:
            print("[FRIDA on_message handler error]", e)
    return on_message

def attach_frida_via_api(package_name: str, script_path: str, duration: Optional[int] = None):
    frida = _ensure_frida_module()
    if not frida:
        print("[*] frida python module not installed; will fallback to CLI background mode.")
        return False
    pid = _adb_get_pid(package_name)
    if not pid:
        print("[!] PID not found (app not running). Start the app first or use spawn).")
        return False
    print(f"[*] Attaching via frida-python API to PID {pid}...")
    try:
        device = frida.get_usb_device(timeout=5)
    except Exception as e:
        print("[!] Cannot get USB device via frida:", e)
        return False
    try:
        session = device.attach(int(pid))
    except Exception as e:
        print("[!] Failed to attach to PID:", e)
        return False
    try:
        js_src = Path(script_path).read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print("[!] Failed to read frida script:", e)
        session.detach()
        return False
    try:
        script = session.create_script(js_src)
    except Exception as e:
        print("[!] Failed to create script object:", e)
        session.detach()
        return False
    script.on("message", _on_message_factory())
    try:
        script.load()
        print("[*] Frida script loaded via API. Hooks installed.")
    except Exception as e:
        print("[!] Error loading frida script:", e)
        try:
            session.detach()
        except Exception:
            pass
        return False
    try:
        if duration and duration > 0:
            print(f"[*] Session will run for {duration} seconds. Interact with app to generate logs.")
            start = time.time()
            while time.time() - start < duration:
                time.sleep(0.5)
        else:
            print("[*] Session active (API). Press Ctrl+C to stop.")
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("[*] KeyboardInterrupt received — detaching frida session...")
    except Exception as e:
        print("[!] Exception while session active:", e)
    finally:
        try:
            session.detach()
            print("[*] Detached from process.")
        except Exception as e:
            print("[!] Error detaching session:", e)
    return True

def attach_frida_fallback_cli_background(package_name: str, script_path: str):
    pid = _adb_get_pid(package_name)
    if not pid:
        print("[!] PID not found, ensure the app is running.")
        return False
    print(f"[*] Found PID: {pid}. Launching frida CLI in background (logs -> {FRIDA_CLI_LOG})")
    cmd = ["frida", "-U", "-p", pid, "-l", script_path]
    try:
        logf = open(str(FRIDA_CLI_LOG), "a", encoding="utf-8")
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=logf, stderr=logf, creationflags=creationflags)
        print(f"[*] frida CLI background pid {p.pid}")
        return True
    except Exception as e:
        print("[!] Failed to launch frida CLI:", e)
        return False

# ========== MAIN ==========
def main():
    print("[*] Starting MASTG Automated Log Analysis Toolkit...")
    static_csv = static_analysis_apk(APK_PATH)
    dynamic_log = monitor_logcat(APP_PACKAGE, duration=45)
    native_csv = analyze_native_libs(APK_PATH)
    # Try frida-python API first; if not available, fallback to CLI background
    api_ok = attach_frida_via_api(APP_PACKAGE, FRIDA_SCRIPT_PATH, duration=120)  # run API session for 120s by default
    if not api_ok:
        # fallback to CLI background (non-blocking)
        attach_frida_fallback_cli_background(APP_PACKAGE, FRIDA_SCRIPT_PATH)
    print("[+] All tasks completed successfully.")

if __name__ == "__main__":
    main()
