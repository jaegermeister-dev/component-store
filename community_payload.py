"""Model-filtered, verified Windows 7 payload staging (no driver execution).

Development manifests originate in audited source hashes, not a folder sweep.
Release callers must separately verify the finished normal-UAC installer and
bundle provenance. This module alone does not make a ready driver installer.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil

MODELS=('MacBookPro11,5','MacBookPro11,4')
SHARED=('Cirrus-Audio','Apple-Trackpad','Apple-Bluetooth','Intel-MEI','Broadcom-WiFi',
        'Apple-Keyboard','BootCamp-Utility','BootCamp-ControlPanel','Microsoft-SHA2-Update','Apple-Keyboard-Layouts','BootCamp-Dependencies','Apple-Identification','Intel-Identification')
AMD=('AMD-M370X','AMD-HDMI-Audio')
INTEL=('Intel-Iris','Intel-HDMI-Audio')


def require(value,message):
    if not value:raise ValueError(message)


def relative(value):
    require(type(value) is str and value and not value.startswith('/') and '\\' not in value
            and ':' not in value and all(ord(x)>=32 for x in value),'Unsafe payload path')
    require(all(p and p not in ('.','..') for p in value.split('/')),'Unsafe payload path')
    return value


def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda:stream.read(1024**2),b''):h.update(data)
    return h.hexdigest()


def select_files(manifest,model,family,opt_in):
    if not opt_in:return []
    require(model in MODELS and family=='Windows 7','Community pack is only for Windows 7 on 11,5/11,4')
    require(manifest.get('status')=='PASS' and manifest.get('private_engineering_only') is True,
            'Expected the audited private payload inventory')
    rows=manifest.get('files')
    require(type(rows) is list and 0<len(rows)<=4096,'Invalid payload inventory')
    found=set();selected=[];components=set()
    for row in rows:
        path=relative(row['path']);parts=path.split('/')
        require(len(parts)>=3 and parts[0]=='Payload' and parts[1] in SHARED+AMD+INTEL,'Unexpected component path')
        require(path.casefold() not in found,'Duplicate/case-colliding payload path');found.add(path.casefold())
        require(type(row.get('bytes')) is int and 0<row['bytes']<=1024**3,'Invalid payload file size')
        require(type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'Invalid payload digest')
        permitted=(['MacBookPro11,5'] if parts[1] in AMD else ['MacBookPro11,4'] if parts[1] in INTEL else list(MODELS))
        require(type(row.get('models')) is list and sorted(row['models'])==sorted(permitted),
                'Payload model policy disagrees with the component')
        if model in permitted:
            components.add(parts[1])
            # Strip source paths/private machine locations from delivered data.
            selected.append(dict(path=path,bytes=row['bytes'],sha256=row['sha256'],component=parts[1]))
    require(components==set(SHARED+(AMD if model=='MacBookPro11,5' else INTEL)), 'Incomplete component inventory')
    return selected


def stage(manifest,source,destination,model,family,opt_in):
    rows=select_files(manifest,model,family,opt_in)
    if not rows:return dict(status='skipped',files=[],drivers_executed=False)
    source=Path(source);destination=Path(destination)
    require(source.is_absolute() and source.is_dir() and source.resolve()==source,'Source path is not canonical')
    require(destination.is_absolute() and destination.resolve()==destination and not destination.exists(),
            'Use a new canonical driver staging directory')
    require(source!=destination and source not in destination.parents,'Do not stage inside the source payload')
    require(destination.parent.is_dir(),'Staging parent missing')
    require(shutil.disk_usage(destination.parent).free>sum(r['bytes'] for r in rows)+16*1024**2,
            'Insufficient staging space')
    # Verify the complete selected input BEFORE writing the staging directory.
    for row in rows:
        path=source/row['path']
        require(path.is_file() and not path.is_symlink() and path.resolve()==path,
                'Missing or linked driver file: '+row['path'])
        require(path.stat().st_size==row['bytes'] and digest(path)==row['sha256'],
                'Driver payload verification failed: '+row['path'])
    destination.mkdir(mode=0o700)
    for row in rows:
        src=source/row['path'];dst=destination/row['path']
        require(src.resolve()==src and not src.is_symlink(),'Driver source changed')
        dst.parent.mkdir(parents=True,exist_ok=True)
        with src.open('rb') as inp,dst.open('xb') as output:shutil.copyfileobj(inp,output,1024**2)
        require(dst.stat().st_size==row['bytes'] and digest(dst)==row['sha256'],
                'Driver copy verification failed: '+row['path'])
    result=dict(schema=1,status='payload-staged-not-installer-ready',model=model,family=family,files=rows,
        drivers_executed=False,installer_complete=False,normal_uac_required=True,
        private_engineering_only=True,excluded_amd=(model=='MacBookPro11,4'))
    (destination/'payload.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
