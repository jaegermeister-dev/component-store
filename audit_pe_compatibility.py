"""Read-only PE import/export compatibility audit; never loads a DLL."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


class PE:
    def __init__(self,path):
        self.path=Path(path);self.data=self.path.read_bytes();d=self.data
        assert d[:2]==b'MZ'
        pe=self.u32(0x3c);assert d[pe:pe+4]==b'PE\0\0'
        self.machine,self.sections=struct.unpack_from('<HH',d,pe+4)
        optsize=self.u16(pe+20);self.opt=pe+24;magic=self.u16(self.opt)
        assert magic in (0x10b,0x20b);self.width=8 if magic==0x20b else 4
        self.dirs=self.opt+(112 if self.width==8 else 96)
        self.headers=self.u32(self.opt+60);section_start=self.opt+optsize
        self.maps=[]
        for i in range(self.sections):
            pos=section_start+i*40;virtual,addr,raw,offset=struct.unpack_from('<IIII',d,pos+8)
            self.maps.append((addr,raw,offset))
    def u16(self,p):return struct.unpack_from('<H',self.data,p)[0]
    def u32(self,p):return struct.unpack_from('<I',self.data,p)[0]
    def offset(self,rva,size=1):
        if rva<self.headers and rva+size<=self.headers:return rva
        for start,raw,offset in self.maps:
            if start<=rva and rva+size<=start+raw and offset+rva-start+size<=len(self.data):return offset+rva-start
        raise ValueError('Unbacked RVA '+hex(rva))
    def string(self,rva):
        start=self.offset(rva);end=self.data.index(0,start,start+4096)
        return self.data[start:end].decode('ascii')
    def imports(self):
        rva,size=struct.unpack_from('<II',self.data,self.dirs+8)
        if not rva:return []
        result=[]
        for i in range(1024):
            pos=self.offset(rva+i*20,20);orig,stamp,forward,name,first=struct.unpack_from('<IIIII',self.data,pos)
            if not any((orig,stamp,forward,name,first)):return result
            dll=self.string(name);functions=[]
            for j in range(65536):
                entry=self.offset((orig or first)+j*self.width,self.width)
                value=struct.unpack_from('<Q' if self.width==8 else '<I',self.data,entry)[0]
                if not value:break
                if value>>(self.width*8-1):functions.append(value&0xffff)
                else:functions.append(self.string(value+2))
            else:raise ValueError('Unterminated import thunk')
            result.append(dict(dll=dll,functions=functions))
        raise ValueError('Unterminated imports')
    def exports(self):
        rva,size=struct.unpack_from('<II',self.data,self.dirs)
        if not rva:return {}
        p=self.offset(rva,40)
        base,nfunc,nnames,funcs,names,ordinals=struct.unpack_from('<IIIIII',self.data,p+16)
        assert nfunc<100000 and nnames<=nfunc
        result={}
        for i in range(nfunc):
            addr=self.u32(self.offset(funcs+4*i,4))
            if addr:result[base+i]=self.string(addr) if rva<=addr<rva+size else None
        for i in range(nnames):
            name=self.string(self.u32(self.offset(names+4*i,4)))
            ordinal=base+self.u16(self.offset(ordinals+2*i,2))
            if ordinal in result:result[name]=result[ordinal]
        return result


def audit(exe,system=None):
    pe=PE(exe);assert pe.machine==0x8664 and pe.width==8,'Expected x64 PE'
    subsystem=pe.u16(pe.opt+68);version=(pe.u16(pe.opt+48),pe.u16(pe.opt+50))
    assert subsystem==2 and version<=(6,1),'Expected Windows7 GUI subsystem'
    imports=pe.imports();cache={};hashes={};resolved=[]
    def lookup(dll,name,chain=()):
        dll=dll.lower()
        assert re.fullmatch(r'[a-z0-9_.-]+\.dll',dll),'Unsafe DLL name'
        assert len(chain)<16 and (dll,name) not in chain,'Export forwarding cycle'
        if dll not in cache:
            path=Path(system)/dll
            assert path.is_file(),'Missing stock Windows7 DLL '+dll
            obj=PE(path);assert obj.machine==0x8664
            cache[dll]=obj.exports();hashes[dll]=hashlib.sha256(obj.data).hexdigest()
        assert name in cache[dll],'Missing Windows7 export '+dll+'!'+str(name)
        forward=cache[dll][name]
        if forward:
            lib,func=forward.rsplit('.',1)
            return lookup(lib+'.dll',int(func[1:]) if func.startswith('#') else func,chain+((dll,name),))
        return dll+'!'+str(name)
    if system:
        for item in imports:
            for name in item['functions']:resolved.append(lookup(item['dll'],name))
    return dict(exe=str(exe),sha256=hashlib.sha256(pe.data).hexdigest(),subsystem=subsystem,
                subsystem_version=version,imports=imports,windows7_exports_verified=bool(system),
                resolved_count=len(resolved),windows7_dll_sha256=hashes,
                no_code_loaded=True,driver_installed=False)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('exe');p.add_argument('--system32')
    a=p.parse_args();print(json.dumps(audit(a.exe,a.system32),indent=2))
