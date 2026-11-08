# Windows 7 / PowerShell 2.0. Exact-version, user-mode utility correction only.
# No driver, trust, UAC, service, startup or firmware settings are changed.
param([ValidateSet('Inspect','Apply','Restore','SelfTest')][string]$Mode='Inspect',
      [string]$TestOriginal)
$ErrorActionPreference='Stop'
$originalHash='d07ea8eedbe29a93f899befbf4df6995f291e7ea80b3aea2b0158d7f15c98d2c'
$correctedHash='97051c55d0155197b02060a7f10323464c7954f09660ef9ecb346b60be7a0eb2'
function HashBytes([byte[]]$data) {
 $h=[Security.Cryptography.SHA256]::Create()
 try{return ([BitConverter]::ToString($h.ComputeHash($data))).Replace('-','').ToLowerInvariant()}finally{$h.Clear()}
}
function FileHash([string]$path){return HashBytes ([IO.File]::ReadAllBytes($path))}
function CorrectedBytes([byte[]]$data) {
 if((HashBytes $data)-ne$originalHash){throw 'Unrecognised Apple utility. No patch applied.'}
 $offset=59580;$expected=[byte[]]@(255,21,190,203,26,0)
 for($i=0;$i-lt6;$i++){if($data[$offset+$i]-ne$expected[$i]){throw 'Preference-flush instruction differs'}}
 $result=[byte[]]$data.Clone()
 for($i=0;$i-lt6;$i++){$result[$offset+$i]=144}
 if((HashBytes $result)-ne$correctedHash){throw 'Corrected utility hash mismatch'}
 return ,$result
}
if($Mode-eq'SelfTest'){
 if(!$TestOriginal){throw 'SelfTest requires an original file; it never writes it.'}
 $raw=[IO.File]::ReadAllBytes($TestOriginal);$fixed=CorrectedBytes $raw
 $changes=@();for($i=0;$i-lt$raw.Length;$i++){if($raw[$i]-ne$fixed[$i]){$changes+=$i}}
 if($changes.Count-ne6-or$changes[0]-ne59580-or$changes[5]-ne59585){throw 'Unexpected patch extent'}
 $rejected=$false;try{[void](CorrectedBytes $fixed)}catch{$rejected=$true}
 if(!$rejected){throw 'Already modified input was accepted'}
 $bad=[byte[]]$raw.Clone();$bad[0]=$bad[0]-bxor1
 $rejected=$false;try{[void](CorrectedBytes $bad)}catch{$rejected=$true}
 if(!$rejected){throw 'Unrecognised input was accepted'}
 if((FileHash $TestOriginal)-ne$originalHash){throw 'Original changed during test'}
 'PASS: exact six-byte correction, output hash, unknown-input rejection; no files/settings changed.'
 return
}
if([IntPtr]::Size-ne8-or[Environment]::OSVersion.Version.ToString()-notlike'6.1.7601*'){throw 'Windows 7 SP1 x64 only'}
$model=(Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS').SystemProductName
if($model-ne'MacBookPro11,5'){throw 'This correction is validated only for MacBookPro11,5'}
$exe=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Boot Camp\Bootcamp.exe'
$root=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'BackToSeven\BootCamp-Backlight-Response-v1'
$backup=Join-Path $root 'Bootcamp.original.exe'
foreach($p in @($exe,[IO.Path]::GetDirectoryName($exe),$root,[IO.Path]::GetDirectoryName($root))){
 if((Test-Path -LiteralPath $p)-and((Get-Item -LiteralPath $p).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Utility/backup path must not be a reparse point'}
}
$current=FileHash $exe
if(@($originalHash,$correctedHash)-notcontains$current){throw 'Unknown installed utility retained without changes'}
$runKey='SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($runKey)
try{$run=$key.GetValue('Apple_KbdMgr',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}finally{$key.Close()}
if(!$run-or$run-match'[\s"]'-or!(Test-Path -LiteralPath $run)-or(FileHash $run)-ne$current){throw 'Unexpected Apple startup path; retained without changes'}
if($Mode-eq'Inspect'){
 'Model='+$model;'Executable='+$exe;'SHA256='+$current;'Startup='+$run
 if(Test-Path -LiteralPath $backup){'BackupSHA256='+(FileHash $backup)}
 return
}
if(!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Normal administrator approval is required'}
if($Mode-eq'Apply'-and$current-eq$correctedHash){
 if(!(Test-Path -LiteralPath $backup)-or(FileHash $backup)-ne$originalHash){throw 'Corrected utility exists without the verified original backup'}
 'Already applied. Original backup verified. Startup unchanged.';return
}
if($Mode-eq'Restore'-and$current-eq$originalHash){'Original utility already selected; no changes.';return}
[void][IO.Directory]::CreateDirectory($root)
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
foreach($sid in @('S-1-5-18','S-1-5-32-544','S-1-5-32-545')){
 $rights=if($sid-eq'S-1-5-32-545'){[Security.AccessControl.FileSystemRights]::ReadAndExecute}else{[Security.AccessControl.FileSystemRights]::FullControl}
 $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),$rights,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
 $acl.AddAccessRule($rule)
}
[IO.Directory]::SetAccessControl($root,$acl)
if($Mode-eq'Apply'){
 $data=CorrectedBytes ([IO.File]::ReadAllBytes($exe));$wanted=$correctedHash
 if(!(Test-Path -LiteralPath $backup)){[IO.File]::Copy($exe,$backup,$false)}
 if((FileHash $backup)-ne$originalHash){throw 'Original backup verification failed'}
}else{
 if(!(Test-Path -LiteralPath $backup)-or(FileHash $backup)-ne$originalHash){throw 'Verified original backup is required for rollback'}
 $data=[IO.File]::ReadAllBytes($backup);$wanted=$originalHash
}
$stamp=[Guid]::NewGuid().ToString()
$record=Join-Path $root ($Mode+'-'+$stamp+'.xml')
New-Object PSObject -Property @{UTC=[DateTime]::UtcNow.ToString('o');Model=$model;Mode=$Mode;Path=$exe;BeforeSHA256=$current;AfterSHA256=$wanted;StartupUnchanged=$run;OriginalBackup=$backup;OriginalSecurity=[IO.File]::GetAccessControl($exe).GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)} | Export-Clixml -Path $record
$temp=Join-Path ([IO.Path]::GetDirectoryName($exe)) ('BackToSeven-'+$stamp+'.tmp')
$displaced=Join-Path $root ('Bootcamp.before-'+$stamp+'.exe')
try{
 [IO.File]::WriteAllBytes($temp,$data)
 if((FileHash $temp)-ne$wanted){throw 'Staged utility verification failed'}
 # Only the known executable is stopped, if present. Setup requests a normal
 # restart; it never launches the tray utility with administrator privileges.
 foreach($process in @(Get-Process -Name Bootcamp -ErrorAction SilentlyContinue)){
  if($process.MainModule.FileName-ieq$exe){$process.Kill();$process.WaitForExit(10000)|Out-Null;if(!$process.HasExited){throw 'Known utility did not stop'}}
 }
 if((FileHash $exe)-ne$current){throw 'Installed utility changed during preparation'}
 [IO.File]::Replace($temp,$exe,$displaced)
 if((FileHash $exe)-ne$wanted-or(FileHash $displaced)-ne$current){throw 'Installed utility readback failed'}
 'PASS '+$Mode+': utility verified; original backup preserved; startup unchanged. Normal restart loads it.'
 'This modifies only the user-mode utility. Its Apple Authenticode signature no longer validates when corrected. Signed drivers and signature enforcement are unchanged.'
}catch{
 $failure=$_
 if((Test-Path -LiteralPath $displaced)-and(FileHash $displaced)-eq$current-and(FileHash $exe)-eq$wanted){
  [IO.File]::Replace($displaced,$exe,(Join-Path $root ('Bootcamp.failed-'+$stamp+'.exe')))
 }
 throw $failure
}finally{if(Test-Path -LiteralPath $temp){[IO.File]::Delete($temp)}}
