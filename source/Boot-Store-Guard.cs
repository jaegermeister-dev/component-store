using System;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Collections.Generic;
public static class BootStoreGuard {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegLoadAppKey(string p,out IntPtr h,uint a,uint o,uint r);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegOpenKeyEx(IntPtr h,string p,uint o,uint a,out IntPtr k);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegQueryValueEx(IntPtr h,string n,IntPtr r,out uint t,byte[] b,ref uint s);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegEnumKeyEx(IntPtr h,uint i,StringBuilder n,ref uint s,IntPtr r,IntPtr c,IntPtr cs,IntPtr ft);
 [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr h);
 const string Manager="{9dea862c-5cdd-4e70-acc1-f32b344d4795}";
 static byte[] Value(IntPtr root,string key,string name,uint expected) {
  IntPtr h;int e=RegOpenKeyEx(root,key,0,0x20019,out h);if(e!=0)throw new Win32Exception(e);
  try{uint type,size=0;e=RegQueryValueEx(h,name,IntPtr.Zero,out type,null,ref size);
   if(e!=0||type!=expected||size>8192)throw new Exception("Unsupported BCD element");
   byte[] b=new byte[size];e=RegQueryValueEx(h,name,IntPtr.Zero,out type,b,ref size);
   if(e!=0||type!=expected||size!=b.Length)throw new Exception("BCD element changed");return b;
  }finally{RegCloseKey(h);}
 }
 static byte[] Element(IntPtr root,string id,string number,uint kind){return Value(root,"Objects\\"+id+"\\Elements\\"+number,"Element",kind);}
 static string Text(byte[] b){if(b.Length<2||b.Length%2!=0||b[b.Length-1]!=0||b[b.Length-2]!=0)throw new Exception("Invalid BCD text");return Encoding.Unicode.GetString(b,0,b.Length-2);}
 static string Single(byte[] b){string s=Text(b).TrimEnd('\0');Require(s.Length>0&&s.IndexOf('\0')<0,"Invalid single BCD string");return s;}
 static bool Equal(byte[] a,byte[] b){if(a.Length!=b.Length)return false;for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false;return true;}
 public static byte[] Device(Guid disk,Guid partition){byte[] b=new byte[88];Array.Copy(BitConverter.GetBytes(6),0,b,16,4);Array.Copy(BitConverter.GetBytes(72),0,b,24,4);Array.Copy(partition.ToByteArray(),0,b,32,16);Array.Copy(disk.ToByteArray(),0,b,56,16);return b;}
 static void Require(bool ok,string message){if(!ok)throw new Exception(message);}
 public static void Validate(string file,string diskId,string espId,string windowsId) {
  Guid disk=new Guid(diskId),esp=new Guid(espId),win=new Guid(windowsId);
  Require(disk!=esp&&disk!=win&&esp!=win,"Ambiguous boot identity");
  IntPtr root;int error=RegLoadAppKey(file,out root,0x20019,1,0);if(error!=0)throw new Win32Exception(error);
  try{
   string loader=Single(Element(root,Manager,"23000003",1)).ToLowerInvariant();
   Guid parsed=new Guid(loader);Require(loader=="{"+parsed.ToString()+"}","Invalid default loader");
   Require(BitConverter.ToUInt32(Value(root,"Objects\\"+Manager+"\\Description","Type",4),0)==0x10100002,"Not a Windows EFI manager");
   Require(BitConverter.ToUInt32(Value(root,"Objects\\"+loader+"\\Description","Type",4),0)==0x10200003,"Not a normal Windows loader");
   Require(Text(Element(root,Manager,"24000001",7)).ToLowerInvariant()==loader+"\0","Shared Windows boot menu retained");
   Require(Single(Element(root,Manager,"12000002",1)).ToLowerInvariant()==@"\efi\microsoft\boot\bootmgfw.efi","Custom boot path retained");
   Require(Single(Element(root,loader,"12000002",1)).ToLowerInvariant()==@"\windows\system32\winload.efi","Unexpected OS loader");
   Require(Single(Element(root,loader,"22000002",1)).ToLowerInvariant()==@"\windows","Unexpected Windows directory");
   byte[] system=Device(disk,esp),windows=Device(disk,win);
   Require(Equal(Element(root,Manager,"11000001",3),system),"Boot manager belongs to another ESP");
   Require(Equal(Element(root,loader,"11000001",3),windows)&&Equal(Element(root,loader,"21000001",3),windows),"Boot store belongs to another Windows installation");
   IntPtr objects;error=RegOpenKeyEx(root,"Objects",0,0x20019,out objects);if(error!=0)throw new Win32Exception(error);
   List<string> permittedSequence=new List<string>();permittedSequence.Add(loader);
   try{for(uint i=0;;i++){
    StringBuilder name=new StringBuilder(128);uint count=128;error=RegEnumKeyEx(objects,i,name,ref count,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero);
    if(error==259)break;if(error!=0)throw new Win32Exception(error);
    string id=name.ToString().ToLowerInvariant();byte[] raw=Value(root,"Objects\\"+id+"\\Description","Type",4);
    Require(raw.Length==4,"Invalid BCD type");uint type=BitConverter.ToUInt32(raw,0);
    if(type==0x10200003&&id!=loader){
     // A recovery loader is acceptable only if it is explicitly WinPE and its
     // embedded file-device descriptor names the same Windows partition.
     byte[] pe=Element(root,id,"26000022",3),dev=Element(root,id,"11000001",3);
     Require(pe.Length==1&&pe[0]==1&&dev.Length>=142&&dev.Length<=4096,"Another Windows loader is present");
     Require(BitConverter.ToUInt32(dev,16)==0&&BitConverter.ToUInt32(dev,20)==1&&BitConverter.ToUInt32(dev,24)==dev.Length-16&&BitConverter.ToUInt32(dev,32)==3&&BitConverter.ToUInt32(dev,56)==1&&BitConverter.ToUInt32(dev,60)==dev.Length-56&&BitConverter.ToUInt32(dev,64)==5,"Unknown recovery descriptor");
     for(int j=0;j<72;j++)Require(dev[68+j]==windows[16+j],"Foreign recovery device");
     Require(Equal(dev,Element(root,id,"21000001",3)),"Mismatched recovery device");
     permittedSequence.Add(id);
    }
   }}finally{RegCloseKey(objects);}
   IntPtr sequence;error=RegOpenKeyEx(root,"Objects\\"+Manager+"\\Elements\\24000002",0,0x20019,out sequence);
   if(error==0){RegCloseKey(sequence);string rawSequence=Text(Element(root,Manager,"24000002",7)).ToLowerInvariant();
    Require(rawSequence.EndsWith("\0"),"Invalid boot sequence");
    foreach(string target in rawSequence.TrimEnd('\0').Split('\0'))Require(permittedSequence.Contains(target),"Foreign boot sequence retained");
   }else if(error!=2)throw new Win32Exception(error);
  }finally{RegCloseKey(root);}
 }
}
