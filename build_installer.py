"""Build the private native Win7 driver EXE; never execute its install path."""
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent/'source'
PROJECT=HERE.parent
assert len(sys.argv)==4, 'Usage: build_installer.py zig.exe ISCC.exe output-folder'
ZIG=Path(sys.argv[1]).resolve()
COMPILER=Path(sys.argv[2]).resolve()
WORK=Path(sys.argv[3]).resolve();WORK.mkdir()
sys.path.insert(0,str(PROJECT))
from community_payload import select_files
from audit_pe_compatibility import audit


def c_array(name,data):
    lines=['static const unsigned char '+name+'[] = {']
    lines.extend(','.join(str(x) for x in data[i:i+32])+',' for i in range(0,len(data),32))
    return '\n'.join(lines+['};'])


def main():
    source_paths=[HERE/name for name in ('driver_setup.c','Driver-Setup.ps1','Native-Driver-Api.cs','Driver-Setup.iss','Apple-Keyboard-Layout.ps1','Accepted-Hardware.ps1','Apple-Timestamp-Trust.ps1','Apple-Timestamp-Root.crt','BootCamp-Backlight-Response.ps1','Apply-Trackpad-Settings.ps1','BackToSeven-Trackpad-Preferences.exe','trackpad_preferences.c','Repair-Graphics-Boot.ps1','Boot-Partition-Identity.cs','Boot-Store-Guard.cs')]
    source_paths.append(HERE/'Menu-Store-Guard.cs')
    source_bytes={p.name:p.read_bytes() for p in source_paths}
    source_hashes={name:hashlib.sha256(data).hexdigest() for name,data in source_bytes.items()}
    manifest=json.loads((PROJECT/'payload-inventory.json').read_text())
    rows=list({r['path']:r for model in ('MacBookPro11,5','MacBookPro11,4') for r in select_files(manifest,model,'Windows 7',True)}.values())
    root=Path(tempfile.mkdtemp(prefix='build-',dir=WORK)).resolve()
    entries=[]
    csvout=io.StringIO(newline='');writer=csv.writer(csvout);writer.writerow(['Path','Bytes','SHA256','AMD'])
    for row in rows:
        path=row['path'].replace('/','\\');amd=1 if row['component'].startswith('AMD-') else 2 if row['component'] in ('Intel-Iris','Intel-HDMI-Audio') else 0
        entries.append('{L%s,%dULL,%s,%d},'%(json.dumps(path),row['bytes'],json.dumps(row['sha256']),amd))
        writer.writerow([path,row['bytes'],row['sha256'],amd])
    header='static const PackFile pack_files[] = {\n'+'\n'.join(entries)+'\n};\n'
    for name,data in [('backend_script',source_bytes['Driver-Setup.ps1']),
                      ('native_api',source_bytes['Native-Driver-Api.cs']),
                      ('apple_layout_script',source_bytes['Apple-Keyboard-Layout.ps1']),
                      ('graphics_boot_script',source_bytes['Repair-Graphics-Boot.ps1']),
                      ('boot_partition_api',source_bytes['Boot-Partition-Identity.cs']),
                      ('boot_store_guard',source_bytes['Boot-Store-Guard.cs']),
                      ('menu_store_guard',source_bytes['Menu-Store-Guard.cs']),
                      ('accepted_hardware',source_bytes['Accepted-Hardware.ps1']),
                      ('timestamp_trust',source_bytes['Apple-Timestamp-Trust.ps1']),
                      ('timestamp_root',source_bytes['Apple-Timestamp-Root.crt']),
                      ('backlight_script',source_bytes['BootCamp-Backlight-Response.ps1']),
                      ('trackpad_script',source_bytes['Apply-Trackpad-Settings.ps1']),
                      ('trackpad_helper',source_bytes['BackToSeven-Trackpad-Preferences.exe']),
                      ('payload_csv',csvout.getvalue().encode('utf-8'))]:
        header+=c_array(name,data)+'\n'
    (root/'embedded_pack.h').write_text(header)
    engine=root/'Windows7-Driver-Engine.exe'
    env=dict(os.environ,ZIG_LOCAL_CACHE_DIR=str(WORK/'tooling/zig-cache/local'),
             ZIG_GLOBAL_CACHE_DIR=str(WORK/'tooling/zig-cache/global'))
    command=[str(ZIG),'cc','-target','x86_64-windows.win7-gnu','-O2','-Wall','-Wextra','-Werror',
             '-nostdlib','-fno-builtin','-isystem',str(ZIG.parent/'lib/libc/include/any-windows-any'),
             '-Wl,-e,Windows7Entry','-Wl,--subsystem,windows','-I'+str(root),str(HERE/'driver_setup.c'),
             '-lkernel32','-lbcrypt','-lshell32','-ladvapi32','-lole32','-luser32',
             '-Wl,--major-subsystem-version,6','-Wl,--minor-subsystem-version,1','-o',str(engine)]
    subprocess.run(command,env=env,check=True,timeout=600)
    fixture=root/'sha256-self-test-input.txt';fixture.write_bytes(b'abc')
    subprocess.run([str(engine),'--self-test',str(fixture)],check=True,timeout=30)
    pe=audit(engine)
    assert {item['dll'].lower() for item in pe['imports']}<={'kernel32.dll','bcrypt.dll','shell32.dll','advapi32.dll','ole32.dll','user32.dll'}, 'Unexpected runtime dependency'
    (root/'pe-imports.json').write_text(json.dumps(pe,indent=2)+'\n')
    compiler=COMPILER
    subprocess.run([str(compiler),'/Qp','/DEngine='+str(engine),'/DBuildOutput='+str(root),
                    str(HERE/'Driver-Setup.iss')],check=True,timeout=180)
    exe=root/'Windows7-Driver-Setup.exe'
    assert all(p.read_bytes()==source_bytes[p.name] for p in source_paths), 'Sources changed during build; rebuild before using it'
    result=dict(status='built-native-self-test-passed',exe=str(exe),bytes=exe.stat().st_size,
        sha256=hashlib.sha256(exe.read_bytes()).hexdigest(),payload_files=len(rows),
        engine=str(engine),engine_sha256=hashlib.sha256(engine.read_bytes()).hexdigest(),
        wizard='Inno Setup 6.7.3',
        original_drivers_installed=False,windows7_runtime_tested=False,ready_for_owner_test=False,
        source_sha256=source_hashes)
    (root/'build-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__=='__main__':main()
