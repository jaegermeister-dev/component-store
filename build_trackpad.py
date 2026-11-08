"""Build only the standalone Win7 normal-user trackpad helper, not the app."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys

here = Path(__file__).resolve().parent/'source'
work = here.parent
assert len(sys.argv)==2, 'Usage: build_trackpad.py /path/to/zig.exe'
zig = Path(sys.argv[1]).resolve()
sys.path.insert(0,str(work))
from audit_pe_compatibility import audit

source = here / "trackpad_preferences.c"
source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
exe = here / "BackToSeven-Trackpad-Preferences.exe"
env = dict(os.environ, ZIG_LOCAL_CACHE_DIR=str(work / "tooling/zig-cache/local"),
           ZIG_GLOBAL_CACHE_DIR=str(work / "tooling/zig-cache/global"))
subprocess.run([
    str(zig), "cc", "-target", "x86_64-windows.win7-gnu", "-O2", "-Wall", "-Wextra", "-Werror",
    "-nostdlib", "-fno-builtin", "-isystem", str(zig.parent / "lib/libc/include/any-windows-any"),
    "-Wl,-e,Windows7Entry", "-Wl,--subsystem,windows", str(source),
    "-lkernel32", "-ladvapi32", "-lshell32", "-luser32",
    "-Wl,--major-subsystem-version,6", "-Wl,--minor-subsystem-version,1", "-o", str(exe)
], env=env, check=True, timeout=300)
pe = audit(exe)
assert {v["dll"].lower() for v in pe["imports"]} <= {"kernel32.dll", "advapi32.dll", "shell32.dll", "user32.dll"}
assert hashlib.sha256(source.read_bytes()).hexdigest() == source_sha
result = dict(bytes=exe.stat().st_size, sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
              source_sha256=source_sha, pe=pe, hardware_tested=False)
(here / "build-result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
