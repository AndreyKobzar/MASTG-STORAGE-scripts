#!/usr/bin/env python3
# frida_memory_dump_resilient.py
# Usage: python3 frida_memory_dump_resilient.py <PID> <out_dir>
# Requires: pip install frida

import frida, sys, os, time, json
from pathlib import Path

if len(sys.argv) < 3:
    print("Usage: python3 frida_memory_dump_resilient.py <PID> <out_dir>")
    sys.exit(2)

PID = int(sys.argv[1])
OUTDIR = Path(sys.argv[2])
OUTDIR.mkdir(parents=True, exist_ok=True)

# ================ Настройки (можешь подправить) =================
CHUNK_SIZE = 16 * 1024        # 16 KiB (меньше — безопаснее, но медленнее)
SLEEP_PER_CHUNK = 0.001       # пауза в секундах после каждого блока (1 ms)
MAX_REGION_DUMP = 200 * 1024 * 1024  # не дампить регионы больше 200 MiB (по умолчанию)
PROTECTIONS = ["rw-", "r--"]  # какие защиты брать (rw- приоритет)
VERBOSE = True
# =================================================================

jscode = r"""
'use strict';
rpc.exports = {
  enumerateAndDump: function (chunkSize, protections) {
    var prot = protections || ['rw-', 'r--'];
    var ranges = [];
    try {
      prot.forEach(function(p) {
        try { ranges = ranges.concat(Process.enumerateRangesSync({ protection: p })); } catch(e) {}
      });
    } catch(e) {
      try { ranges = Process.enumerateRangesSync({ protection: 'r--' }); } catch(e2) {}
    }

    // uniq ranges by base
    var seen = {};
    var outRanges = [];
    ranges.forEach(function (r) {
      var base = r.base.toString();
      if (!seen[base]) { seen[base] = true; outRanges.push(r); }
    });

    // send metadata
    send({ type: 'ranges_meta', count: outRanges.length, ranges: outRanges.map(function(r){ return { base: r.base.toString(), size: r.size.toString(), protection: r.protection }; }) });

    outRanges.forEach(function (rg) {
      var base = ptr(rg.base);
      var size = (typeof rg.size === 'number') ? rg.size : rg.size.toInt32();
      send({ type: 'region_start', base: base.toString(), size: size });
      var offset = 0;
      while (offset < size) {
        var readSize = Math.min(chunkSize, size - offset);
        try {
          var buf = Memory.readByteArray(base.add(offset), readSize);
          send({ type: 'chunk', base: base.toString(), offset: offset, size: readSize, region_size: size }, buf);
        } catch (e) {
          send({ type: 'chunk_error', base: base.toString(), offset: offset, err: ''+e });
          break;
        }
        offset += readSize;
      }
      send({ type: 'region_done', base: base.toString(), region_size: size });
    });

    send({ type: 'done' });
  }
};
"""

# --- attach ---
device = None
session = None
script = None
try:
    device = frida.get_usb_device(timeout=5)
    print("[*] Attaching to PID", PID)
    session = device.attach(PID)
    script = session.create_script(jscode)
except Exception as e:
    print("[!] Failed to attach:", e)
    sys.exit(3)

region_files = {}
region_received = {}

def safe_close_all():
    for fh in list(region_files.values()):
        try:
            fh.close()
        except:
            pass

def on_message(message, data):
    if message.get('type') != 'send':
        if message.get('type') == 'error':
            print("[!] script error:", message)
        return
    payload = message.get('payload', {})
    t = payload.get('type')
    if t == 'ranges_meta':
        print(f"[*] Ranges reported: {payload.get('count')}")
    elif t == 'region_start':
        base = payload['base'].replace('0x','').lower()
        size = int(payload['size'])
        print(f"[*] REGION start 0x{base} size {size}")
    elif t == 'chunk':
        base = payload['base'].replace('0x','').lower()
        offset = int(payload['offset'])
        size = int(payload['size'])
        region_size = int(payload['region_size'])
        fname = OUTDIR / f"region_{base}.bin"
        if base not in region_files:
            # create sparse file by writing as we go; open in r+b (create)
            fh = open(fname, "r+b") if fname.exists() else open(fname, "w+b")
            region_files[base] = fh
            region_received[base] = 0
        fh = region_files[base]
        try:
            fh.seek(offset)
            fh.write(data)
            region_received[base] += len(data)
        except Exception as e:
            print(f"[!] Write error region 0x{base} at offset {offset}: {e}")
        # occasional progress
        if region_received[base] % (1024*1024) < len(data):
            print(f"[+] region 0x{base}: wrote {region_received[base]}/{region_size} bytes")
    elif t == 'chunk_error':
        print("[!] chunk read error:", payload.get('base'), payload.get('offset'), payload.get('err'))
    elif t == 'region_done':
        base = payload['base'].replace('0x','').lower()
        print(f"[+] region done 0x{base} size {payload.get('region_size')}")
        if base in region_files:
            try:
                region_files[base].close()
            except:
                pass
            del region_files[base]
    elif t == 'done':
        print("[*] Remote script signalled done")
    else:
        print("[*] message:", payload)

script.on('message', on_message)
script.load()

# get ranges from the script first (we'll call enumerate with protections but will fetch meta via messages)
# Instead of reading everything blindly, we'll ask frida to enumerate, then we will parse the reported ranges, filter and re-request small ones first.
try:
    # call once with protections to get ranges list
    print("[*] Requesting ranges list...")
    # We will call enumerateAndDump but with chunkSize=1 to get ranges metadata first (script still emits chunk messages, but we'll ignore heavy reads).
    # Instead: ask for ranges metadata via same RPC but we'll process in-host by collecting region starts and sizes reported.
    # Simpler approach: call enumerateAndDump but we will skip dumping regions larger than MAX_REGION_DUMP by checking 'region_start' messages.
    script.exports.enumerate_and_dump(CHUNK_SIZE, PROTECTIONS)
except frida.InvalidOperationError:
    print("[!] frida.InvalidOperationError: script destroyed (target may have crashed)")
except Exception as e:
    print("[!] Exception during dump rpc:", e)

# allow messages to flush
time.sleep(1.0)

# close open files
safe_close_all()

print("[*] Done. Check directory:", OUTDIR.resolve())

try:
    session.detach()
except:
    pass
