Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class AppleOfflineSignature {
[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct FileInfo {public uint size;[MarshalAs(UnmanagedType.LPWStr)]public string path;public IntPtr file,subject;}
[StructLayout(LayoutKind.Sequential)]struct Trust {public uint size;public IntPtr policy,sip;public uint ui,revocation,choice;public IntPtr info;public uint stateAction;public IntPtr state,url;public uint flags,uiContext;}
[DllImport("wintrust.dll",ExactSpelling=true)]static extern int WinVerifyTrust(IntPtr hwnd,ref Guid action,ref Trust data);
public static string Verify(string p){FileInfo f=new FileInfo();f.size=(uint)Marshal.SizeOf(typeof(FileInfo));f.path=p;IntPtr b=Marshal.AllocHGlobal((int)f.size);Marshal.StructureToPtr(f,b,false);Trust t=new Trust();t.size=(uint)Marshal.SizeOf(typeof(Trust));t.ui=2;t.choice=1;t.info=b;t.stateAction=1;t.flags=0x1000;Guid a=new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");try{return "0x"+WinVerifyTrust(new IntPtr(-1),ref a,ref t).ToString("X8");}finally{t.stateAction=2;WinVerifyTrust(new IntPtr(-1),ref a,ref t);Marshal.DestroyStructure(b,typeof(FileInfo));Marshal.FreeHGlobal(b);}}
}
'@
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class W7DEPTimestampOnly {
 [StructLayout(LayoutKind.Sequential)] struct Usage {public uint count; public IntPtr oids;}
 [DllImport("crypt32.dll",SetLastError=true)] static extern bool CertSetEnhancedKeyUsage(IntPtr c,ref Usage u);
 [DllImport("crypt32.dll",SetLastError=true)] static extern bool CertGetEnhancedKeyUsage(IntPtr c,uint flags,IntPtr u,ref uint size);
 [DllImport("crypt32.dll",SetLastError=true)] public static extern IntPtr CertOpenStore(IntPtr provider,uint encoding,IntPtr crypt,uint flags,IntPtr para);
 [DllImport("crypt32.dll",SetLastError=true)] public static extern bool CertCloseStore(IntPtr store,uint flags);
 [DllImport("crypt32.dll",SetLastError=true)] public static extern bool CertFreeCertificateContext(IntPtr c);
 [DllImport("crypt32.dll",SetLastError=true)] static extern bool CertAddCertificateContextToStore(IntPtr store,IntPtr cert,uint disposition,out IntPtr copy);
 public static void Restrict(IntPtr cert) {
  IntPtr oid=Marshal.StringToHGlobalAnsi("1.3.6.1.5.5.7.3.8"), list=Marshal.AllocHGlobal(IntPtr.Size);
  try {Marshal.WriteIntPtr(list,oid);Usage u=new Usage();u.count=1;u.oids=list;if(!CertSetEnhancedKeyUsage(cert,ref u))throw new Win32Exception();}
  finally {Marshal.FreeHGlobal(list);Marshal.FreeHGlobal(oid);}
 }
 public static string Read(IntPtr cert) {
  uint size=0;if(!CertGetEnhancedKeyUsage(cert,4,IntPtr.Zero,ref size))throw new Win32Exception();
  IntPtr p=Marshal.AllocHGlobal((int)size);
  try {if(!CertGetEnhancedKeyUsage(cert,4,p,ref size))throw new Win32Exception();Usage u=(Usage)Marshal.PtrToStructure(p,typeof(Usage));if(u.count!=1)throw new Exception("Not exactly one allowed EKU");return Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(u.oids));}
  finally {Marshal.FreeHGlobal(p);}
 }
 public static IntPtr AddNew(IntPtr store,IntPtr cert) {IntPtr copy;if(!CertAddCertificateContextToStore(store,cert,1,out copy))throw new Win32Exception();return copy;}
}
'@
function EnsureAppleTimestampTrust([string[]]$Drivers) {
 $needs=$false
 foreach($file in $Drivers){if([AppleOfflineSignature]::Verify($file)-ne'0x00000000'){$needs=$true}}
 if(!$needs){return}
 $thumb='3679CA35668772304D30A5FB873B0FA77BB70D54'
 $sha='2399561127a57125de8cefea610ddf2fa078b5c8067f4e828290bfb860e84b3c'
 $path=Join-Path $PackRoot 'Apple-Timestamp-Root.crt'
 if((Hash $path)-ne$sha){throw 'Pinned timestamp certificate mismatch'}
 $cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2
 $cert.Import($path)
 if($cert.Thumbprint-ne$thumb-or$cert.Subject-ne$cert.Issuer){throw 'Timestamp certificate identity mismatch'}
 foreach($location in @('LocalMachine','CurrentUser')){
  $disallowed=New-Object Security.Cryptography.X509Certificates.X509Store('Disallowed',$location)
  try{$disallowed.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly);if(@($disallowed.Certificates|Where-Object {$_.Thumbprint-eq$thumb}).Count){throw 'Timestamp root explicitly disallowed; no repair applied'}}finally{$disallowed.Close()}
 }
 $store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')
 $added=$false;$accepted=$false
 try{
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  if(@($store.Certificates|Where-Object {$_.Thumbprint-eq$thumb}).Count){throw 'Existing root retained; signature failure requires review'}
  [W7DEPTimestampOnly]::Restrict($cert.Handle)
  $copy=[W7DEPTimestampOnly]::AddNew($store.StoreHandle,$cert.Handle);$added=$true
  try{if([W7DEPTimestampOnly]::Read($copy)-ne'1.3.6.1.5.5.7.3.8'){throw 'Timestamp-only restriction lost'}}finally{[void][W7DEPTimestampOnly]::CertFreeCertificateContext($copy)}
  foreach($file in $Drivers){if([AppleOfflineSignature]::Verify($file)-ne'0x00000000'){throw 'Original Apple signature still fails; added root will be rolled back'}}
  ('Added only '+$thumb+' restricted to time stamping; SHA256='+$sha+'. Rollback: remove only this exact root if still matching and timestamp-only. No signing-policy bypass.')|Out-File (Join-Path $PackRoot 'timestamp-root-receipt.txt')
  $accepted=$true
 }finally{
  if($added-and!$accepted){foreach($c in @($store.Certificates|Where-Object {$_.Thumbprint-eq$thumb})){if([W7DEPTimestampOnly]::Read($c.Handle)-eq'1.3.6.1.5.5.7.3.8'){$store.Remove($c)}}}
  $store.Close()
 }
 Note 'Original Apple signatures validate after the targeted timestamp-only trust repair.'
}
