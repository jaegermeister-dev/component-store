using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class BootPartitionIdentity {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle h,uint c,IntPtr i,uint il,byte[] o,uint ol,out uint n,IntPtr v);
 static byte[] Query(string path,uint code) {
  using(SafeFileHandle h=CreateFile(path,0,3,IntPtr.Zero,3,0,IntPtr.Zero)) {
   if(h.IsInvalid)throw new Win32Exception();
   byte[] b=new byte[65536];uint n;
   if(!DeviceIoControl(h,code,IntPtr.Zero,0,b,(uint)b.Length,out n,IntPtr.Zero))throw new Win32Exception();
   if(n>b.Length)throw new Exception("Oversize disk response");Array.Resize(ref b,(int)n);return b;
  }
 }
 static Guid Id(byte[] b,int offset){byte[] g=new byte[16];Array.Copy(b,offset,g,0,16);return new Guid(g);}
 public static string[] Parse(byte[] extent,byte[] layout) {
  if(extent.Length<32||BitConverter.ToUInt32(extent,0)!=1)throw new Exception("Expected one volume extent");
  if(layout.Length<48||BitConverter.ToUInt32(layout,0)!=1)throw new Exception("Expected GPT disk");
  uint count=BitConverter.ToUInt32(layout,4);if(count==0||count>256||48L+144L*count>layout.Length)throw new Exception("Invalid GPT response size");
  long start=BitConverter.ToInt64(extent,16),length=BitConverter.ToInt64(extent,24);
  if(start<=0||length<=0||Id(layout,8)==Guid.Empty)throw new Exception("Invalid GPT/extent identity");
  string[] found=null;
  for(int i=0;i<count;i++) {int off=48+i*144;
   if(BitConverter.ToUInt32(layout,off)!=1)throw new Exception("Mixed partition style");
   if(BitConverter.ToInt64(layout,off+8)==start&&BitConverter.ToInt64(layout,off+16)==length){
    if(found!=null)throw new Exception("Ambiguous partition");
    found=new string[]{Id(layout,8).ToString(),Id(layout,off+48).ToString(),Id(layout,off+32).ToString()};
   }
  }
  if(found==null)throw new Exception("Volume partition not found");return found;
 }
 public static string[] Read(string drive) {
  if(drive==null||drive.Length!=2||drive[1]!=':'||drive[0]<'A'||drive[0]>'Z')throw new Exception("Invalid drive");
  byte[] e=Query(@"\\.\"+drive,0x00560000);
  if(e.Length<32||BitConverter.ToUInt32(e,0)!=1)throw new Exception("Expected one extent");
  return Parse(e,Query(@"\\.\PhysicalDrive"+BitConverter.ToUInt32(e,8),0x00070050));
 }
}
