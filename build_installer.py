"""Developer build only. No dependencies are required by the finished EXE.

Usage: python build_installer.py /absolute/path/to/zig /new/output/directory
The recipe supplies file hashes, not vendor bytes. This never installs drivers.
"""
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys


def c_array(name, data):
    lines = ['static const unsigned char '+name+'[] = {']
    lines.extend(','.join(str(x) for x in data[i:i+32])+',' for i in range(0,len(data),32))
    return '\n'.join(lines+['};'])


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    here = Path(__file__).resolve().parent
    zig = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2]).resolve()
    output.mkdir(parents=False, exist_ok=False)
    source = here/'source'
    files = {n:(source/n).read_bytes() for n in ('driver_setup.c','Driver-Setup.ps1','Native-Driver-Api.cs')}
    recipe = json.loads((here/'driver-recipe-development.json').read_text())
    rows = recipe['files']
    entries = []; csvout = io.StringIO(newline=''); writer = csv.writer(csvout)
    writer.writerow(['Path','Bytes','SHA256','AMD'])
    for row in rows:
        path = row['path'].replace('/','\\')
        amd = int(row['component'] in ('AMD-M370X','AMD-HDMI-Audio'))
        entries.append('{L%s,%dULL,%s,%d},' % (json.dumps(path),row['bytes'],json.dumps(row['sha256']),amd))
        writer.writerow([path,row['bytes'],row['sha256'],amd])
    header = 'static const PackFile pack_files[] = {\n'+'\n'.join(entries)+'\n};\n'
    for name,data in [('backend_script',files['Driver-Setup.ps1']),
                      ('native_api',files['Native-Driver-Api.cs']),
                      ('payload_csv',csvout.getvalue().encode('utf-8'))]:
        header += c_array(name,data)+'\n'
    (output/'embedded_pack.h').write_text(header)
    exe = output/'NoMoreBCA-Driver-Setup.exe'
    env = dict(os.environ, ZIG_LOCAL_CACHE_DIR=str(output/'cache-local'),
               ZIG_GLOBAL_CACHE_DIR=str(output/'cache-global'))
    subprocess.run([str(zig),'cc','-target','x86_64-windows.win7-gnu','-O2','-Wall','-Wextra','-Werror',
        '-nostdlib','-fno-builtin','-isystem',str(zig.parent/'lib/libc/include/any-windows-any'),
        '-Wl,-e,NoMoreBCAEntry','-Wl,--subsystem,windows','-I'+str(output),str(source/'driver_setup.c'),
        '-lkernel32','-lbcrypt','-lshell32','-ladvapi32','-lole32','-luser32',
        '-Wl,--major-subsystem-version,6','-Wl,--minor-subsystem-version,1','-o',str(exe)],
        check=True, env=env, timeout=600)
    self_test = False
    if sys.platform == 'win32':
        fixture = output/'sha256-self-test-input.txt'; fixture.write_bytes(b'abc')
        subprocess.run([str(exe),'--self-test',str(fixture)],check=True,timeout=30)
        self_test = True
    result = dict(bytes=exe.stat().st_size,sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
        source_sha256={n:hashlib.sha256(b).hexdigest() for n,b in files.items()},
        payload_files=len(rows),read_only_self_test_passed=self_test,drivers_installed=False)
    (output/'build-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':main()
