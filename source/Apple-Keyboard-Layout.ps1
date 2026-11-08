# Windows 7 PS2/CLR2. Register runs elevated; Apply runs as the original user.
# No key hooks, key-state capture, input injection, driver binding, or security changes.
param([ValidateSet('Register','Apply','SelfTest','Inspect','Verify')][string]$Mode='Inspect',[string]$PackRoot)
$ErrorActionPreference='Stop'
$catalog=@'
Standard,KLID,LayoutID,Name,File,Bytes,SHA256
00000405,a0000405,00d4,Czech (Apple),CzechA.dll,13752,e780ce0ba85ceccad97a1fe837074d00ca34e15d2460be916c25c04bf5e717b4
00000406,a0000406,00cc,Danish (Apple),DanishA.dll,13240,f6a08175dc15242409a31dae1fcaf4e05572c129cb9f12a5b6b45b7c217d0378
00000407,a0000407,00c3,German (Apple),GermanA.dll,12728,8db73a634e1a8a69369e63654beef7fdc9ffcaa00173b4fa403f513fa51e5654
00000409,a0000409,00d1,United States (Apple),USA.dll,12216,52d8fb00d0d84fee3c77932f3d3d6c38f2c91ded3bfcd04dc7082c952fe12a11
0000040a,a000040a,00c5,Spanish (Apple),SpanishA.dll,13240,3ba84bf71a7fc15318c478298b590a04bd3d6c882fa5c223e2d5eabcca47bbba
0000040b,a000040b,00cb,Finnish (Apple),FinnishA.dll,13240,aae71bcb00a26edc542118bb8b429191732fa5ff557ad6cb0128c34e358a5c9d
0000040c,a000040c,00c2,French (Apple),FrenchA.dll,13240,95624f459522112b20848c60a0e0b2bc9721d7ce6a9c28aeffa2a91424bcc935
0000040e,a000040e,00d5,Hungarian (Apple),HungaryA.dll,13752,3636145c4f1949f093e7a2118ef5aef78d9836bc20d8906663fab40032dc5dc8
00000410,a0000410,00c4,Italian (Apple),ItalianA.dll,12728,73fc96a4f68c772255c97d80a1053b357f70d9a95b200e90434ce668c0a5ed36
00000413,a0000413,00c1,Dutch (Apple),DutchA.dll,13240,e3a49b6736954918c9808b70aac857e7df3d8f94ee295cfe9fd8063939c0612e
00000414,a0000414,00c9,Norwegian (Apple),NorwayA.dll,13240,12e15afd8af66281e7a8f41f6635123138cf48b3d79220eff8d904b110e89d91
00000415,a0000415,00cf,Polish (Apple),PolishA.dll,14264,d2345bda3029fb4f9213fe43c7174ecf4725b9a91690f7abc2ff8f7edebb7731
00000416,a0000416,00ce,Portuguese (Apple),PortuguA.dll,13240,3dd3ff17d48c2893d0e5609eb755db5b453dc29cf83ee41656fcc6147083e19a
00000419,a0000419,00c8,Russian (Apple),RussianA.dll,12728,e9ed275af21ec14d288549ede1c1ab009b0ff06ab393d36c89f5245092cf4795
0000041d,a000041d,00c7,Swedish (Apple),SwedishA.dll,13240,ada9f088325390e5c18888a0ef01143377c11b328857a2aa93541e2443758197
0000041f,a000041f,00d3,Turkish Q (Apple),TurkeyQA.dll,13240,d367c6b3718ad40526e2c4b52dc65211b838a0150509b660a1dab1b5ea914094
00000809,a0000809,00c0,United Kingdom (Apple),BritishA.dll,12728,805020fdce3798472fd6245f2e3ed9828dc2461aa568bd14362403f0ef39c476
00000813,a0000813,00cd,Belgian (Apple),BelgiumA.dll,13752,c0861af76fe0dd3779eefe55dad1c12e61e8c0cbf829b67f8ba099bf2e79098e
00000c0c,a0000c0c,00ca,Canadian Multilingual (Apple),CanadaA.dll,13752,8852d99e2379c4e0bb99598a75f65717a81332af06f3dd266d48b769d178cf06
0000100c,a000100c,00c6,Swiss (Apple),SwissA.dll,13240,5bbbb553703c0ab8ba30aaeca3e6bb48e042c806a1f7d808229df19167229808
00020409,a0020409,00d0,United States-International (Apple),IntlEngA.dll,12728,d0929f8a7f3f7289da5a7e75f4aecca5f2ddb8cdb40b91b8264bf36861caaec0
0001041f,a100041f,00d2,Turkish F (Apple),TurkeyA.dll,13240,7fcaaf86f9efcb3ae1f9ee094d2d4f4db910d4a18c3014b46cf231efff919744
'@ | ConvertFrom-Csv
function LayoutHash([string]$p){
 $s=[IO.File]::OpenRead($p);$h=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($h.ComputeHash($s))).Replace('-','').ToLowerInvariant()}finally{$s.Close();$h.Clear()}
}
function SelectAppleLayout([string]$current){
 return @($catalog|Where-Object {$_.Standard-eq$current -or $_.KLID-eq$current})
}
function ReadPreloads {
 $k=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Keyboard Layout\Preload')
 if(!$k){throw 'Current user has no keyboard layout preferences'}
 try{
  $names=@($k.GetValueNames()|Sort-Object {[int]$_})
  foreach($n in $names){
   if($n-notmatch'^[1-9][0-9]*$' -or $k.GetValueKind($n)-ne[Microsoft.Win32.RegistryValueKind]::String){throw 'Unexpected keyboard preference format'}
   $v=[string]$k.GetValue($n)
   if($v-notmatch'^[0-9a-fA-F]{8}$'){throw 'Unexpected keyboard identifier'}
   New-Object PSObject -Property @{Name=$n;Value=$v}
  }
 }finally{$k.Close()}
}
function AssertLayout($r,[string]$file){
 if(!(Test-Path -LiteralPath $file) -or (Get-Item -LiteralPath $file).Length-ne[long]$r.Bytes -or (LayoutHash $file)-ne$r.SHA256){throw ('Apple layout hash/size mismatch: '+$r.File)}
}
function AssertRegistration($r){
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Keyboard Layouts\'+$r.KLID)
 if(!$key){throw ('Apple keyboard layout is not registered: '+$r.Name)}
 try{
  foreach($pair in @(@('Layout Text',$r.Name),@('Layout File',$r.File),@('Layout Id',$r.LayoutID))){
   if($key.GetValue($pair[0])-ne$pair[1] -or $key.GetValueKind($pair[0])-ne[Microsoft.Win32.RegistryValueKind]::String){throw 'Apple layout registration differs from its original metadata'}
  }
 }finally{$key.Close()}
}
if($Mode-eq'SelfTest'){
 if(@($catalog).Count-ne22 -or @(SelectAppleLayout '00000809')[0].KLID-ne'a0000809' -or @(SelectAppleLayout '00000409')[0].File-ne'USA.dll' -or @(SelectAppleLayout '00020409')[0].File-ne'IntlEngA.dll' -or @(SelectAppleLayout '0001041f')[0].File-ne'TurkeyA.dll'){throw 'Layout selection regression'}
 if(@(SelectAppleLayout '00000411').Count-ne0){throw 'Unmatched language must not be replaced by UK/US'}
 if(@($catalog|Group-Object KLID|Where-Object {$_.Count-ne1}).Count -or @($catalog|Group-Object LayoutID|Where-Object {$_.Count-ne1}).Count){throw 'Duplicate layout registration'}
 'PASS: UK, US, international, Turkish variants and unmatched-language policy; no settings changed.';exit 0
}
if([IntPtr]::Size-ne8 -or [Environment]::OSVersion.Version.ToString()-notlike'6.1.7601*'){throw 'Windows 7 SP1 x64 only'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$admin=(New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$base='SYSTEM\CurrentControlSet\Control\Keyboard Layouts'
if($Mode-eq'Register' -or $Mode-eq'Verify'){
 if(!$admin){throw 'Administrator authorization required to install original Apple layouts'}
 Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class AppleLayoutTrust {
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct FileInfo {public uint size;[MarshalAs(UnmanagedType.LPWStr)]public string path;public IntPtr file,subject;}
 [StructLayout(LayoutKind.Sequential)]struct Trust {public uint size;public IntPtr policy,sip;public uint ui,revocation,choice;public IntPtr info;public uint stateAction;public IntPtr state,url;public uint flags,uiContext;}
 [DllImport("wintrust.dll",ExactSpelling=true)]static extern int WinVerifyTrust(IntPtr hwnd,ref Guid action,ref Trust data);
 public static int Verify(string p){
  FileInfo f=new FileInfo();f.size=(uint)Marshal.SizeOf(typeof(FileInfo));f.path=p;
  IntPtr b=Marshal.AllocHGlobal((int)f.size);Marshal.StructureToPtr(f,b,false);
  Trust t=new Trust();t.size=(uint)Marshal.SizeOf(typeof(Trust));t.ui=2;t.choice=1;t.info=b;t.stateAction=1;
  // Cache-only chain verification: this offline installer must not wait for Internet access.
  t.flags=0x1000;Guid a=new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
  try{return WinVerifyTrust(new IntPtr(-1),ref a,ref t);}finally{t.stateAction=2;WinVerifyTrust(new IntPtr(-1),ref a,ref t);Marshal.DestroyStructure(b,typeof(FileInfo));Marshal.FreeHGlobal(b);}
 }
}
'@
 $backup=Join-Path $PackRoot 'backup-Apple-Keyboard-Layouts'
 if($Mode-eq'Register' -and (Test-Path -LiteralPath $backup)){throw 'Use a fresh installer session; prior layout records retained'}
 # Validate all sources and existing state before creating any registration.
 foreach($r in $catalog){
  $src=Join-Path $PackRoot ('Payload\Apple-Keyboard-Layouts\'+$r.File)
  AssertLayout $r $src
  $sig=New-Object Security.Cryptography.X509Certificates.X509Certificate2([Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($src))
  if([AppleLayoutTrust]::Verify($src)-ne0 -or $sig.Thumbprint-ne'3CB392CDACBC2D564B1E474BD4B81E58A1F244C3'){throw ('Original Apple signature not accepted: '+$r.File)}
  $dst=Join-Path "$env:WINDIR\System32" $r.File
  if(Test-Path -LiteralPath $dst){AssertLayout $r $dst}
  if(Test-Path -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\'+$base+'\'+$r.KLID)){AssertRegistration $r}
 }
 foreach($k in Get-ChildItem ('Registry::HKEY_LOCAL_MACHINE\'+$base)){
  $v=Get-ItemProperty -LiteralPath $k.PSPath
  foreach($r in $catalog){if($v.'Layout Id'-eq$r.LayoutID -and $k.PSChildName-ne$r.KLID){throw ('Layout ID collision: '+$r.LayoutID)}}
 }
 if($Mode-eq'Verify'){'PASS: 22 original layout hashes/signatures and existing registration/collision checks; cache-only trust, no changes.';exit 0}
 [void][IO.Directory]::CreateDirectory($backup)
 $created=@()
 try{
  foreach($r in $catalog){
   $src=Join-Path $PackRoot ('Payload\Apple-Keyboard-Layouts\'+$r.File);$dst=Join-Path "$env:WINDIR\System32" $r.File
   $keyPath=$base+'\'+$r.KLID
   $fileNew=!(Test-Path -LiteralPath $dst);$keyNew=!(Test-Path -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\'+$keyPath))
   $created+=New-Object PSObject -Property @{KLID=$r.KLID;File=$dst;FileNew=$fileNew;KeyNew=$keyNew;SHA256=$r.SHA256}
   $created|Export-Clixml -Path (Join-Path $backup 'created.xml')
   if($fileNew){[IO.File]::Copy($src,$dst,$false)}
   AssertLayout $r $dst
   if($keyNew){
    $key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($keyPath)
    try{foreach($pair in @(@('Layout Text',$r.Name),@('Layout File',$r.File),@('Layout Id',$r.LayoutID))){$key.SetValue($pair[0],$pair[1],[Microsoft.Win32.RegistryValueKind]::String)}}finally{$key.Close()}
   }
   AssertRegistration $r
  }
  [IO.File]::WriteAllText((Join-Path $backup 'result.txt'),'Original signed Apple layouts registered and verified. User preference application is a separate normal-user stage. Existing layouts retained.')
  [IO.File]::WriteAllText((Join-Path $PackRoot 'apple-layouts-ready.txt'),'Apple layouts registered; apply to original interactive user.')
  'PASS: 22 original Apple keyboard layouts registered and hash/signature verified.'
 }catch{
  $_|Out-String|Out-File -FilePath (Join-Path $backup 'failure.txt')
  throw
 }
 exit 0
}
# Apply must run in the user's interactive session, not SSH/LocalSystem or a
# different administrator's profile used only for UAC credentials.
if([Diagnostics.Process]::GetCurrentProcess().SessionId-eq0){throw 'Run user layout stage in the original interactive user session'}
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;using System.ComponentModel;
public static class AppleLayoutUser {
 [DllImport("user32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadKeyboardLayoutW(string name,uint flags);
 [DllImport("user32.dll",SetLastError=true)] static extern bool SystemParametersInfoW(uint action,uint param,ref IntPtr value,uint flags);
 [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr window,uint msg,IntPtr wp,IntPtr lp);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int ToUnicodeEx(uint vk,uint scan,byte[] state,StringBuilder text,int capacity,uint flags,IntPtr hkl);
 public static IntPtr Default(){IntPtr h=IntPtr.Zero;if(!SystemParametersInfoW(0x59,0,ref h,0))throw new Win32Exception(Marshal.GetLastWin32Error());return h;}
 public static IntPtr Load(string klid,string id){
  IntPtr h=LoadKeyboardLayoutW(klid,0x101);if(h==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
  uint expected=((0xf000U|Convert.ToUInt32(id,16))<<16)|Convert.ToUInt32(klid.Substring(4),16);
  if(unchecked((uint)h.ToInt64())!=expected)throw new InvalidOperationException("Fallback layout was loaded instead of Apple layout");
  if(klid=="a0000809"){
   byte[] state=new byte[256];state[0x10]=0x80;StringBuilder text=new StringBuilder(8);
   if(ToUnicodeEx(0x32,3,state,text,8,0,h)!=1||text[0]!='@')throw new InvalidOperationException("Apple UK Shift+2 mapping failed");
  }
  return h;
 }
 // Windows 7 rejects SPIF_UPDATEINIFILE for this action. Preload persistence
 // is saved separately; SPIF_SENDCHANGE updates the shell's current default.
 public static void SetDefault(IntPtr h){if(!SystemParametersInfoW(0x5a,0,ref h,2))throw new Win32Exception(Marshal.GetLastWin32Error());if(Default()!=h)throw new InvalidOperationException("Default input layout readback failed");}
 public static void NotifyApplications(IntPtr h){PostMessageW(new IntPtr(0xffff),0x50,IntPtr.Zero,h);}
}
'@
$before=@(ReadPreloads)
if(!$before.Count -or $before[0].Name-ne'1'){throw 'Cannot determine current keyboard layout'}
$current=$before[0].Value
$sub=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Keyboard Layout\Substitutes')
try{if($sub -and $sub.GetValue($current)){$current=[string]$sub.GetValue($current)}}finally{if($sub){$sub.Close()}}
$selected=@(SelectAppleLayout $current)
if($selected.Count-ne1){'No exact Apple equivalent for '+$current+'. Current language preserved; installed Apple layouts remain available in Control Panel.';exit 2}
$r=$selected[0];AssertRegistration $r;AssertLayout $r (Join-Path "$env:WINDIR\System32" $r.File)
$oldDefault=[AppleLayoutUser]::Default()
if($Mode-eq'Inspect'){'User='+$identity.Name+' Preload='+$before[0].Value+' DefaultHKL='+([uint32]($oldDefault.ToInt64()-band0xffffffffL)).ToString('X8');exit 0}
$record=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('BackToSeven\Keyboard-Layout-'+[Guid]::NewGuid().ToString())
[void][IO.Directory]::CreateDirectory($record)
$before|Export-Clixml -Path (Join-Path $record 'preload-before.xml')
[IO.File]::WriteAllText((Join-Path $record 'before.txt'),('User='+$identity.User.Value+'; defaultHKL='+$oldDefault.ToInt64().ToString('X')))
$loaded=[AppleLayoutUser]::Load($r.KLID,$r.LayoutID)
$values=@($r.KLID)+@($before|Where-Object {$_.Value-ne$r.KLID}|ForEach-Object {$_.Value})
$modified=$false
try{
 $now=@(ReadPreloads)
 if(($now|ForEach-Object {$_.Name+'='+$_.Value}|Out-String)-ne($before|ForEach-Object {$_.Name+'='+$_.Value}|Out-String)){throw 'Keyboard preferences changed during setup'}
 $k=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Keyboard Layout\Preload',$true)
 try{
  $modified=$true
  foreach($n in $k.GetValueNames()){$k.DeleteValue($n)}
  for($i=0;$i-lt$values.Count;$i++){$k.SetValue(($i+1).ToString(),$values[$i],[Microsoft.Win32.RegistryValueKind]::String)}
 }finally{$k.Close()}
 [AppleLayoutUser]::SetDefault($loaded)
 if(@(ReadPreloads)[0].Value-ne$r.KLID){throw 'Persistent keyboard default readback failed'}
 [AppleLayoutUser]::NotifyApplications($loaded)
 $result='PASS: '+$r.Name+' automatically selected; persistent default='+$r.KLID+'; shell defaultHKL='+([uint32]($loaded.ToInt64()-band0xffffffffL)).ToString('X8')+'; previous layouts retained. Session='+[Diagnostics.Process]::GetCurrentProcess().SessionId+'; Elevated='+$admin
 if($r.KLID-eq'a0000809'){$result+='; Shift+2 mapping verified as @.'}
 [IO.File]::WriteAllText((Join-Path $record 'result.txt'),$result)
 $result;'Backup='+$record
}catch{
 $failure=$_
 if($modified){
  $now=@(ReadPreloads|ForEach-Object {$_.Value})
  if(($now-join',')-eq($values-join',')){
   $k=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Keyboard Layout\Preload',$true)
   try{foreach($n in $k.GetValueNames()){$k.DeleteValue($n)};foreach($v in $before){$k.SetValue($v.Name,$v.Value,[Microsoft.Win32.RegistryValueKind]::String)}}finally{$k.Close()}
   if([AppleLayoutUser]::Default()-eq$loaded){[AppleLayoutUser]::SetDefault($oldDefault)}
  }
 }
 [IO.File]::WriteAllText((Join-Path $record 'failure.txt'),$failure.ToString());throw $failure
}
