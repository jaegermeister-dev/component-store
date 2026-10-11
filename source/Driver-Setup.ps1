# Windows 7 PowerShell 2.0 syntax only. Embedded by the native EXE, not a
# prerequisite download. No networking, UAC changes, signing bypass or reboot.
param([string]$PackRoot,[string]$ExpectedModel,[switch]$SelfTest)
$ErrorActionPreference='Stop'

function Hash([string]$Path) {
 $stream=[IO.File]::OpenRead($Path);$hash=[Security.Cryptography.SHA256]::Create()
 try {return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}
 finally {$stream.Close();$hash.Clear()}
}
function Relative([string]$Path) {
 if(!$Path -or $Path -match '(^[\\/]|/|:|["*?]|[\x00-\x1f])' -or @($Path.Split('\')|Where-Object {$_ -eq '' -or $_ -eq '.' -or $_ -eq '..'}).Count){throw 'Unsafe payload path'}
 return $Path
}
function Original([string]$Relative) {
 $relative=Relative $Relative;$path=Join-Path $PackRoot $relative
 $row=@($script:Inventory|Where-Object {$_.Path -eq $relative})
 if($row.Count -ne 1 -or !(Test-Path -LiteralPath $path) -or (Get-Item -LiteralPath $path).Length -ne [long]$row[0].Bytes -or (Hash $path) -ne $row[0].SHA256){throw ('Verified payload changed: '+$relative)}
 return $path
}
function Trusted([string]$Path) {
 # PowerShell 2 has FilePath only (verified against the stock Win7 assembly).
 $s=Get-AuthenticodeSignature -FilePath $Path
 if($s.Status -ne 'Valid'){throw ('Windows did not trust the original signature: '+$Path+'. No signature bypass will be used.')}
 return $s
}
function Note([string]$Message) {
 $line=(Get-Date -Format o)+' '+$Message
 $line|Out-File -FilePath (Join-Path $PackRoot 'setup.log') -Encoding utf8 -Append
 if($script:Log){$script:Log.AppendText($Message+"`r`n");[Windows.Forms.Application]::DoEvents()}
}
function Present([string]$HardwareID) {
 return @(Get-WmiObject Win32_PnPEntity|Where-Object {@($_.HardwareID) -contains $HardwareID})
}
function BackupDevice($Device,[string]$Directory) {
 [void][IO.Directory]::CreateDirectory($Directory)
 $Device|Export-Clixml -Path (Join-Path $Directory 'device-before.xml')
 $key='HKLM\SYSTEM\CurrentControlSet\Enum\'+$Device.PNPDeviceID
 & "$env:SystemRoot\System32\reg.exe" export $key (Join-Path $Directory 'device-before.reg') /y|Out-Null
 if($LASTEXITCODE -ne 0){throw 'Device registry backup failed'}
 $props=Get-ItemProperty -LiteralPath ('Registry::'+$key)
 if($props.Driver){
  $driver=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\'+$props.Driver)
  $driver|Export-Clixml -Path (Join-Path $Directory 'driver-before.xml')
  if($driver.InfPath -and $driver.InfPath -notmatch '[\\/:]'){
   $inf=Join-Path "$env:SystemRoot\inf" $driver.InfPath
   if(Test-Path -LiteralPath $inf){[IO.File]::Copy($inf,(Join-Path $Directory ('previous-'+$driver.InfPath)),$false)}
  }
 }
 if(Test-Path -LiteralPath "$env:SystemRoot\inf\setupapi.dev.log"){[IO.File]::Copy("$env:SystemRoot\inf\setupapi.dev.log",(Join-Path $Directory 'setupapi-before.log'),$false)}
 'Use Device Manager > device > Driver > Roll Back Driver if needed. Previous device/INF state is preserved here. Do not blindly import an entire registry backup.'|Out-File -FilePath (Join-Path $Directory 'ROLLBACK.txt') -Encoding utf8
}
function InstallINF($Component) {
 $inf=Original $Component.Inf;$catalog=Original $Component.Catalog
 [void](Trusted $catalog)
 $devices=@(Present $Component.HardwareID)
 if(!$devices.Count){Note ($Component.Name+': matching hardware is absent; skipped.');return}
 $backup=Join-Path $PackRoot ('backup-'+$Component.Name)
 if(Test-Path -LiteralPath $backup){throw 'This session already attempted the component. Close and rerun the EXE for a new verified session.'}
 $i=0;foreach($dev in $devices){BackupDevice $dev (Join-Path $backup ('device-'+$i));$i++}
 try {
  $reboot=[NoMoreBCADriverApi]::Install($script:Form.Handle,$Component.HardwareID,$inf)
  if($reboot){$script:RebootNeeded=$true}
  $after=@(Present $Component.HardwareID);$after|Export-Clixml -Path (Join-Path $backup 'devices-after.xml')
  Note ($Component.Name+': Windows accepted installation. Restart required='+$reboot+'. Physical functions still require testing.')
  foreach($dev in $after){Note ('  '+$dev.Name+': device status '+$dev.ConfigManagerErrorCode)}
 } catch {
  $_|Out-String|Out-File -FilePath (Join-Path $backup 'failure.txt') -Encoding utf8
  throw
 } finally {
  if(Test-Path -LiteralPath "$env:SystemRoot\inf\setupapi.dev.log"){[IO.File]::Copy("$env:SystemRoot\inf\setupapi.dev.log",(Join-Path $backup 'setupapi-after.log'),$true)}
 }
}
function InstallSigningUpdate {
 $installed=@(Get-WmiObject Win32_QuickFixEngineering|Where-Object {$_.HotFixID -eq 'KB3033929' -or $_.HotFixID -eq 'KB4474419'})
 if($installed.Count){Note 'SHA-2 support update is already recorded.';return}
 $msu=Original 'Payload\Microsoft-SHA2-Update\Windows6.1-KB3033929-x64.msu'
 Note 'Installing the original Microsoft SHA-2 update. Windows servicing may take several minutes.'
 $process=Start-Process -FilePath "$env:SystemRoot\System32\wusa.exe" -ArgumentList ('"'+$msu+'" /quiet /norestart') -WindowStyle Hidden -PassThru -Wait
 $process.ExitCode|Out-File -FilePath (Join-Path $PackRoot 'sha2-servicing-exit.txt') -Encoding ascii
 # WUSA success/already installed; 3010 means do not attempt drivers until the
 # owner's ordinary reboot. Never create an elevated persistence task.
 if($process.ExitCode -eq 3010){$script:RebootNeeded=$true;throw 'The Microsoft update requires a restart. Restart normally when ready, then run driver setup again.'}
 if($process.ExitCode -ne 0 -and $process.ExitCode -ne 2359302){throw ('Microsoft update did not complete: '+$process.ExitCode)}
 if(Test-Path -LiteralPath "$env:SystemRoot\winsxs\pending.xml"){$script:RebootNeeded=$true;throw 'Windows servicing is pending. Restart normally, then rerun setup.'}
 Note 'Microsoft update completed; no signing-policy change.'
}
function InstallTrackpad {
 $devices=@(Present 'USB\VID_05AC&PID_0274&MI_02')
 if($devices.Count -ne 1){throw 'Expected one supported Apple trackpad interface; no filter changed.'}
 $dev=$devices[0];$id=$dev.PNPDeviceID;$key='HKLM:\SYSTEM\CurrentControlSet\Enum\'+$id
 $source=Original 'Payload\Apple-Trackpad\AppleMTP.sys'
 $inf=Original 'Payload\Apple-Trackpad\AppleMTP64.inf'
 $cat=Original 'Payload\Apple-Trackpad\AppleMTP64.cat';[void](Trusted $cat)
 foreach($item in @(@($source,'6B2F843AE6CA1069F020A8DEFD683251C339A63AEE8AB5179D416EDA7C1EE54C'),@($inf,'29216B4C8DAFBA55FF4D6635A4BE1F58E78402309817C0D8736E86262D2B07EC'))){
  if([NoMoreBCADriverApi]::VerifyMember($cat,$item[0],$item[1]) -ne 0){throw 'Original Apple trackpad catalog-member validation failed.'}
 }
 $destination="$env:SystemRoot\System32\drivers\AppleMTP.sys"
 $svc='HKLM:\SYSTEM\CurrentControlSet\Services\applemtp'
 $filters=@((Get-ItemProperty -LiteralPath $key).LowerFilters|Where-Object {$_})
 if($filters -contains 'applemtp' -and (Test-Path -LiteralPath $destination) -and (Hash $destination) -eq (Hash $source)){
  Note 'Original Apple trackpad filter is already attached. Enable your preferred options in Boot Camp Control Panel.';return
 }
 if((Test-Path -LiteralPath $svc) -or (Test-Path -LiteralPath $destination) -or $filters.Count -or $dev.Service -ne 'HidUsb' -or $dev.ConfigManagerErrorCode -ne 0){throw 'Existing trackpad/filter state differs; retained without replacement.'}
 $wdf=(Get-Item -LiteralPath "$env:SystemRoot\System32\drivers\Wdf01000.sys").VersionInfo
 if($wdf.FileMajorPart -ne 1 -or $wdf.FileMinorPart -lt 11){throw 'KMDF 1.11 is not present yet. Install the selected Apple keyboard driver first and restart if requested.'}
 $backup=Join-Path $PackRoot 'backup-Apple-Trackpad';BackupDevice $dev $backup
 $catName='nomorebca-applemtp-'+[Guid]::NewGuid().ToString()+'.cat'
 $catPath=$null;$fileCopied=$false;$serviceCreated=$false;$filterApplied=$false
 try {
  $catPath=[NoMoreBCADriverApi]::Catalog($cat,$catName,$false)
  if((Hash $catPath) -ne (Hash $cat)){throw 'Registered catalog readback failed'}
  [IO.File]::Copy($source,$destination,$false);$fileCopied=$true
  if((Hash $destination) -ne (Hash $source)){throw 'Trackpad driver readback failed'}
  & "$env:SystemRoot\System32\sc.exe" create applemtp type= kernel start= demand error= normal binPath= '\SystemRoot\System32\drivers\AppleMTP.sys' DisplayName= 'Apple Multi-Touch'|Out-Null
  if($LASTEXITCODE -ne 0){throw 'Trackpad service creation failed'};$serviceCreated=$true
  & "$env:SystemRoot\System32\sc.exe" description applemtp 'NoMoreBCA verified Apple trackpad package 1'|Out-Null
  if($LASTEXITCODE -ne 0){throw 'Trackpad service receipt failed'}
  [void](New-ItemProperty -LiteralPath $svc -Name HotspringTrackpads -PropertyType MultiString -Value @('VID_05AC&PID_0273','VID_05AC&PID_0274','VID_05AC&PID_0290','VID_05AC&PID_0291'))
  [void](New-Item -Path ($svc+'\Parameters\Wdf') -Force)
  [void](New-ItemProperty -LiteralPath ($svc+'\Parameters\Wdf') -Name KmdfLibraryVersion -PropertyType String -Value '1.11')
  [NoMoreBCADriverApi]::SetLowerFilters($id,[string[]]@('applemtp'));$filterApplied=$true
  if([NoMoreBCADriverApi]::Restart($id)){$script:RebootNeeded=$true}
  @(Present 'USB\VID_05AC&PID_0274&MI_02')|Export-Clixml -Path (Join-Path $backup 'device-after.xml')
  $driver=Get-WmiObject Win32_SystemDriver -Filter "Name='applemtp'"
  $driver|Export-Clixml -Path (Join-Path $backup 'driver-after.xml')
  if(!$script:RebootNeeded -and (!$driver -or $driver.State -ne 'Running' -or $driver.ExitCode -ne 0)){throw 'Trackpad filter did not start'}
  New-Object PSObject -Property @{Device=$id;Catalog=$catPath;Driver=$destination;SHA256=(Hash $source);BeforeLowerFilters=@();OriginalServiceAbsent=$true}|Export-Clixml -Path (Join-Path $backup 'owned-changes.xml')
  Note 'Original Apple trackpad filter attached. Use Boot Camp Control Panel to enable tapping, secondary click and scrolling. No global mouse/keyboard filter changed.'
 } catch {
  $originalFailure=$_;$_|Out-String|Out-File -FilePath (Join-Path $backup 'failure.txt') -Encoding utf8
  try {
   if($filterApplied){$now=@((Get-ItemProperty -LiteralPath $key).LowerFilters|Where-Object {$_});if($now.Count -ne 1 -or $now[0] -ne 'applemtp'){throw 'Filter changed since installation; not overwriting it.'};[NoMoreBCADriverApi]::SetLowerFilters($id,[string[]]@());if([NoMoreBCADriverApi]::Restart($id)){$script:RebootNeeded=$true}}
   $driver=Get-WmiObject Win32_SystemDriver -Filter "Name='applemtp'"
   if($driver -and $driver.State -eq 'Running'){throw 'Basic input restored; the filter is still loaded. Restart before any owned-file cleanup.'}
   if($serviceCreated){& "$env:SystemRoot\System32\sc.exe" delete applemtp|Out-Null;if($LASTEXITCODE -ne 0){throw 'Service rollback failed'}}
   if($fileCopied -and (Hash $destination) -eq (Hash $source)){[IO.File]::Delete($destination)}
   if($catPath -and (Hash $catPath) -eq (Hash $cat)){[void][NoMoreBCADriverApi]::Catalog($null,$catName,$true)}
   Note 'Failed trackpad attempt rolled back to the original basic HID input.'
  } catch {$_|Out-String|Out-File -FilePath (Join-Path $backup 'rollback-attention.txt') -Encoding utf8;Note ('Rollback needs attention: '+$_)}
  throw $originalFailure
 }
}
function ControlPanelRegistryPlan([string]$Folder) {
 $clsid='SOFTWARE\Classes\CLSID\{4d0f8110-1de4-11dc-8314-0800200c9a66}'
 $namespace='SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{4d0f8110-1de4-11dc-8314-0800200c9a66}'
 $items=@(
  @($clsid,'','Boot Camp','String'),
  @($clsid,'System.ApplicationName','Apple.ControlPanel','String'),
  @($clsid,'System.ControlPanel.Category','5','String'),
  @($clsid,'LocalizedString','@%SystemRoot%\System32\AppleControlPanel.exe,-109','ExpandString'),
  @($clsid,'InfoTip','@%SystemRoot%\System32\AppleControlPanel.exe,-110','ExpandString'),
  @(($clsid+'\DefaultIcon'),'','%SystemRoot%\System32\AppleControlPanel.exe,-128','ExpandString'),
  @(($clsid+'\Shell\Open\Command'),'','"%SystemRoot%\System32\AppleControlPanel.exe"','ExpandString'),
  @($namespace,'','Apple Control Panel','String'),
  @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run','Apple_KbdMgr',('"'+(Join-Path $Folder 'Bootcamp.exe')+'"'),'String')
 )
 foreach($item in $items){New-Object PSObject -Property @{Key=$item[0];Name=$item[1];Value=$item[2];Kind=$item[3]}}
}
function RegistryDisposition([bool]$Exists,$Value,[string]$Kind,$Expected) {
 if(!$Exists){return 'missing'}
 if($Value -eq $Expected.Value -and $Kind -eq $Expected.Kind){return 'retain'}
 throw ('Different existing Boot Camp registration retained: '+$Expected.Key+' / '+$Expected.Name)
}
function ReadPlannedRegistry($Expected) {
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Expected.Key)
 try {
  if(!$key -or @($key.GetValueNames()) -notcontains $Expected.Name){return 'missing'}
  return RegistryDisposition $true ($key.GetValue($Expected.Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)) ($key.GetValueKind($Expected.Name).ToString()) $Expected
 }finally{if($key){$key.Close()}}
}
function InstallControlPanel {
 $exe=Original 'Payload\BootCamp-Utility\Bootcamp.exe';$resource=Original 'Payload\BootCamp-Utility\Boot Camp.Resources\en.lproj\Resources.dll'
 $panel=Original 'Payload\BootCamp-ControlPanel\AppleControlPanel.exe'
 foreach($p in @($exe,$resource,$panel)){[void](Trusted $p)}
 $programs=[Environment]::GetFolderPath('ProgramFiles');$folder=Join-Path $programs 'Boot Camp'
 $targetPanel="$env:SystemRoot\System32\AppleControlPanel.exe"
 $plan=@(ControlPanelRegistryPlan $folder)
 $backup=Join-Path $PackRoot 'backup-BootCamp-ControlPanel'
 if(Test-Path -LiteralPath $backup){throw 'Rerun the EXE for a new verified session before retrying this component.'}
 [void][IO.Directory]::CreateDirectory($backup)
 $map=@(@($exe,(Join-Path $folder 'Bootcamp.exe')),@($resource,(Join-Path $folder 'Boot Camp.Resources\en.lproj\Resources.dll')),@($panel,$targetPanel))
 foreach($pair in $map){if((Test-Path -LiteralPath $pair[1]) -and (Hash $pair[1]) -ne (Hash $pair[0])){throw ('Different existing Boot Camp file retained: '+$pair[1])}}
 $before=@();foreach($entry in $plan){$before+=New-Object PSObject -Property @{Entry=$entry;State=(ReadPlannedRegistry $entry)}}
 New-Object PSObject -Property @{Files=$map;Registry=$before}|Export-Clixml -Path (Join-Path $backup 'before.xml')
 $ownedFiles=@();$ownedValues=@()
 try {
  foreach($pair in $map){
   if(!(Test-Path -LiteralPath $pair[1])){
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($pair[1]))
    [IO.File]::Copy($pair[0],$pair[1],$false);$ownedFiles+=,$pair
    $ownedFiles|Export-Clixml -Path (Join-Path $backup 'created-files.xml')
   }
   if((Hash $pair[1]) -ne (Hash $pair[0])){throw 'Boot Camp file verification failed'}
  }
  foreach($entry in $plan){
   if((ReadPlannedRegistry $entry) -eq 'retain'){continue}
   $key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($entry.Key)
   try {
    if(@($key.GetValueNames()) -contains $entry.Name){throw 'Registry changed during installation; no existing value overwritten.'}
    $key.SetValue($entry.Name,$entry.Value,[Enum]::Parse([Microsoft.Win32.RegistryValueKind],$entry.Kind))
    $ownedValues+=,$entry;$ownedValues|Export-Clixml -Path (Join-Path $backup 'created-values.xml')
   }finally{$key.Close()}
   if((ReadPlannedRegistry $entry) -ne 'retain'){throw 'Boot Camp registration readback failed'}
  }
 } catch {
  $originalFailure=$_;$failures=@()
  for($i=$ownedValues.Count-1;$i -ge 0;$i--){
   $entry=$ownedValues[$i]
   try {
    if((ReadPlannedRegistry $entry) -eq 'retain'){
     $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($entry.Key,$true)
     try {$key.DeleteValue($entry.Name,$false)}finally{$key.Close()}
    }
   }catch{$failures+=$_.ToString()}
  }
  foreach($pair in $ownedFiles){try {if(Test-Path -LiteralPath $pair[1]){if((Hash $pair[1]) -ne (Hash $pair[0])){throw ('Created file changed; retained '+$pair[1])};[IO.File]::Delete($pair[1])}}catch{$failures+=$_.ToString()}}
  @('Only values/files created by this attempt were considered for rollback. Existing registrations and empty keys/directories were retained.')+$failures|Out-File -FilePath (Join-Path $backup 'rollback.txt') -Encoding utf8
  throw $originalFailure
 }
 'Original Boot Camp tray starts with normal user privileges at the next sign-in. No elevated task/service was installed. Open Control Panel > Boot Camp for trackpad options.'|Out-File -FilePath (Join-Path $backup 'result.txt') -Encoding utf8
 Note 'Boot Camp Control Panel and normal-user tray startup installed. The tray appears at the next sign-in; this installer does not launch it as administrator.'
}
function Components([string]$Model) {
 $items=@(
  @{Name='Microsoft-SHA2-Update';Title='Microsoft SHA-2 signing support (restart may be needed)';Kind='Update'},
  @{Name='Apple-Keyboard';Title='Apple internal keyboard';Kind='INF';HardwareID='USB\VID_05AC&PID_0274&MI_01';Inf='Payload\Apple-Keyboard\Keymagic64.inf';Catalog='Payload\Apple-Keyboard\Keymagic64.cat'},
  @{Name='Broadcom-WiFi';Title='Broadcom Wi-Fi';Kind='INF';HardwareID='PCI\VEN_14E4&DEV_43BA';Inf='Payload\Broadcom-WiFi\bcmpciedhd6.inf';Catalog='Payload\Broadcom-WiFi\bcmpciedhd6.cat'},
  @{Name='Apple-Bluetooth';Title='Apple Bluetooth';Kind='INF';HardwareID='USB\VID_05AC&PID_8290';Inf='Payload\Apple-Bluetooth\AppleBTBC.inf';Catalog='Payload\Apple-Bluetooth\AppleBTBC.cat'},
  @{Name='Intel-MEI';Title='Intel Management Engine interface';Kind='INF';HardwareID='PCI\VEN_8086&DEV_8C3A';Inf='Payload\Intel-MEI\heci.inf';Catalog='Payload\Intel-MEI\heci.cat'},
  @{Name='Cirrus-Audio';Title='Cirrus built-in audio';Kind='INF';HardwareID='HDAUDIO\FUNC_01&VEN_1013&DEV_4208&SUBSYS_106B8000';Inf='Payload\Cirrus-Audio\cs4208_24.inf';Catalog='Payload\Cirrus-Audio\cs4208.cat'}
 )
 if($Model -eq 'MacBookPro11,5'){$items+=@(
  @{Name='AMD-M370X';Title='AMD Radeon R9 M370X graphics';Kind='INF';HardwareID='PCI\VEN_1002&DEV_6821&SUBSYS_0149106B&REV_83';Inf='Payload\AMD-M370X\C7303160.inf';Catalog='Payload\AMD-M370X\C7303160.cat'},
  @{Name='AMD-HDMI-Audio';Title='AMD HDMI audio';Kind='INF';HardwareID='HDAUDIO\FUNC_01&VEN_1002&DEV_AA01&SUBSYS_00AA0100&REV_1003';Inf='Payload\AMD-HDMI-Audio\AtihdW76.inf';Catalog='Payload\AMD-HDMI-Audio\atihdw76.cat'}
 )}
 $items+=@(@{Name='Apple-Trackpad';Title='Apple trackpad (Boot Camp options)';Kind='Trackpad'},@{Name='BootCamp-ControlPanel';Title='Boot Camp Control Panel and tray utility';Kind='ControlPanel'})
 return $items
}

if($SelfTest){
 foreach($bad in @('','..\x','x\..\y','C:\x','\server\x','x:ads','x\\y','x\')){$threw=$false;try{[void](Relative $bad)}catch{$threw=$true};if(!$threw){throw 'Path test failed'}}
 if((Relative 'Payload\Apple-Keyboard\Keymagic.sys') -ne 'Payload\Apple-Keyboard\Keymagic.sys'){throw 'Valid relative path rejected'}
 if(@(Components 'MacBookPro11,4'|Where-Object {$_.Name -like 'AMD-*'}).Count){throw '11,4 AMD exclusion failed'}
 if(@(Components 'MacBookPro11,5'|Where-Object {$_.Name -like 'AMD-*'}).Count -ne 2){throw '11,5 AMD components missing'}
 $panelPlan=@(ControlPanelRegistryPlan 'C:\Program Files\Boot Camp')
 if($panelPlan.Count -ne 9){throw 'Control panel registration plan incomplete'}
 foreach($entry in $panelPlan){
  if((RegistryDisposition $false $null '' $entry) -ne 'missing'){throw 'Missing registration test failed'}
  if((RegistryDisposition $true $entry.Value $entry.Kind $entry) -ne 'retain'){throw 'Idempotent registration test failed'}
  $threw=$false;try{[void](RegistryDisposition $true 'Unrelated existing value' $entry.Kind $entry)}catch{$threw=$true};if(!$threw){throw 'Existing registration protection failed'}
 }
 Add-Type -Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Native-Driver-Api.cs')
 if(![NoMoreBCADriverApi]::LayoutSelfTest()){throw 'Native structure layout mismatch'}
 'PASS: pure policy/path tests and read-only native ABI checks. No driver, registry, UAC or device changes.';exit 0
}

try {
 if([IntPtr]::Size -ne 8 -or [Environment]::OSVersion.Version.ToString() -notlike '6.1.7601*'){throw 'Windows 7 SP1 x64 only'}
 if(!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Use the EXE and approve normal Windows UAC.'}
 $model=(Get-WmiObject Win32_ComputerSystem).Model
 if($model -ne $ExpectedModel -or @('MacBookPro11,5','MacBookPro11,4') -notcontains $model){throw 'Target hardware/model changed'}
 $PackRoot=[IO.Path]::GetFullPath($PackRoot)
 if([IO.Path]::GetDirectoryName($PackRoot) -ne [Environment]::GetFolderPath('CommonApplicationData') -or [IO.Path]::GetFileName($PackRoot) -notlike 'NoMoreBCA-Driver-Setup-{*}'){throw 'Use the EXE-created protected staging directory.'}
 if((Get-Item -LiteralPath $PackRoot).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Staging cannot be a link'}
 $script:Inventory=@(Import-Csv -Path (Join-Path $PackRoot 'expected-files.csv'))
 foreach($row in $script:Inventory){if($row.AMD -eq '1' -and $model -eq 'MacBookPro11,4'){continue};[void](Original $row.Path)}
 Add-Type -Path (Join-Path $PackRoot 'Native-Driver-Api.cs')
 if(![NoMoreBCADriverApi]::LayoutSelfTest()){throw 'Native API layout mismatch'}
 Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing
 [Windows.Forms.Application]::EnableVisualStyles()
 $script:Form=New-Object Windows.Forms.Form;$script:Form.Text='NoMoreBCA - Windows 7 driver setup';$script:Form.Size=New-Object Drawing.Size(790,760);$script:Form.StartPosition='CenterScreen'
 $intro=New-Object Windows.Forms.Label;$intro.Location=New-Object Drawing.Point(18,15);$intro.Size=New-Object Drawing.Size(740,90)
 $intro.Text=$model+" - original signed driver components.`r`nChoose what to install. No Internet connection is needed. UAC and driver-signature enforcement remain unchanged. This private combined installer still needs a fresh-install test."
 if($model -eq 'MacBookPro11,4'){$intro.Text+="`r`n11,4 is untested. No AMD driver is included; Intel graphics support is not established."}
 $script:Form.Controls.Add($intro)
 $script:Choices=New-Object Windows.Forms.CheckedListBox;$script:Choices.Location=New-Object Drawing.Point(18,110);$script:Choices.Size=New-Object Drawing.Size(740,205);$script:Choices.CheckOnClick=$true
 $script:Plan=@(Components $model)
 foreach($c in $script:Plan){$present=$true;if($c.Kind -eq 'INF'){$present=@(Present $c.HardwareID).Count -gt 0};$title=$c.Title;if(!$present){$title+=' (matching hardware not detected)'};[void]$script:Choices.Items.Add($title,$present)}
 $script:Form.Controls.Add($script:Choices)
 $script:Log=New-Object Windows.Forms.TextBox;$script:Log.Location=New-Object Drawing.Point(18,365);$script:Log.Size=New-Object Drawing.Size(740,300);$script:Log.Multiline=$true;$script:Log.ReadOnly=$true;$script:Log.ScrollBars='Vertical';$script:Form.Controls.Add($script:Log)
 $script:Start=New-Object Windows.Forms.Button;$script:Start.Text='Install selected components';$script:Start.Location=New-Object Drawing.Point(18,325);$script:Start.Size=New-Object Drawing.Size(250,30);$script:Form.Controls.Add($script:Start)
 $close=New-Object Windows.Forms.Button;$close.Text='Close';$close.Location=New-Object Drawing.Point(655,680);$close.Size=New-Object Drawing.Size(100,28);$close.Add_Click({$script:Form.Close()});$script:Form.Controls.Add($close)
 $script:Busy=$false;$script:RebootNeeded=$false
 $script:Form.Add_FormClosing({param($sender,$eventArgs);if($script:Busy){$eventArgs.Cancel=$true}})
 $script:Start.Add_Click({
  if($script:Busy){return};$script:Busy=$true;$script:Start.Enabled=$false;$script:Choices.Enabled=$false
  try {
   if(Test-Path -LiteralPath "$env:SystemRoot\winsxs\pending.xml"){throw 'Windows servicing is pending. Restart normally before installing drivers.'}
   $selected=@($script:Choices.CheckedIndices);if(!$selected.Count){Note 'Nothing selected; no driver changes.';return}
   foreach($index in $selected){
    $component=$script:Plan[[int]$index];Note ('Starting '+$component.Title)
    switch($component.Kind){'Update'{InstallSigningUpdate};'INF'{InstallINF $component};'Trackpad'{InstallTrackpad};'ControlPanel'{InstallControlPanel};default{throw 'Unknown component'}}
    if($script:RebootNeeded){Note 'A restart has been requested by Windows. Restart normally, then rerun setup to finish remaining components.';break}
   }
   Note ('Selected pass finished. Restart required='+$script:RebootNeeded+'. No automatic restart. Logs: '+$PackRoot)
   Note 'Fn controls, keyboard backlight, camera and Thunderbolt Ethernet are not claimed fixed by this package. No fan/power settings were changed.'
  } catch {Note ('STOPPED: '+$_);Note ('Prior component results and backups remain in '+$PackRoot+'. No signature/security workaround was applied.')}
  finally {$script:Busy=$false}
 })
 Note 'Ready. Select components and click Install. Close cancels without installing drivers.'
 [void]$script:Form.ShowDialog();exit 0
} catch {
 Add-Type -AssemblyName System.Windows.Forms
 [void][Windows.Forms.MessageBox]::Show($_.ToString(),'NoMoreBCA driver setup',0,16);exit 1
}
