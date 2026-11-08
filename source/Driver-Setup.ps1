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
 $status=[AppleOfflineSignature]::Verify($Path)
 if($status-ne'0x00000000'){throw ('Windows did not trust the original signature: '+$Path+' ('+$status+'). No signature bypass will be used.')}
 return $status
}
function Note([string]$Message) {
 $line=(Get-Date -Format o)+' '+$Message
 if($PackRoot){$line|Out-File -FilePath (Join-Path $PackRoot 'setup.log') -Encoding utf8 -Append}
 [Console]::WriteLine($Message)
}
function Present([string]$HardwareID) {
 # Keep enumeration and exact-ID matching together in native typed code. Use
 # array Length, not the PowerShell extended Count alias, for device results.
 $found=[Windows7DriverApi]::FindPresent($HardwareID)
 Note ('Device query '+$HardwareID+': '+$found.Length+' matching present device(s).')
 return $found
}
function InstalledINF($Device) {
 $key='HKLM:\SYSTEM\CurrentControlSet\Enum\'+$Device.PNPDeviceID
 $props=Get-ItemProperty -LiteralPath $key
 if(!$props.Driver){return ''}
 $driver=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Control\Class\'+$props.Driver)
 if(!$driver.InfPath -or $driver.InfPath -match '[\\/:]'){return ''}
 $path=Join-Path "$env:SystemRoot\inf" $driver.InfPath
 if(!(Test-Path -LiteralPath $path)){return ''}
 return Hash $path
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
 if(!$devices.Length){$script:ComponentState='not-detected';Note ($Component.Name+': not detected in present hardware or compatible IDs. Not installed.');return}
 $expected=Hash $inf
 if(@($devices|Where-Object {(InstalledINF $_) -ne $expected}).Count -eq 0){
  foreach($dev in $devices){if($dev.ConfigManagerErrorCode-eq43-and$script:GraphicsBootRepaired-and$Component.Name-eq'AMD-M370X'){$script:ComponentState='restart-required';Note 'Restart required to activate the repaired graphics EFI route.';return};if($dev.ConfigManagerErrorCode-ne0){throw ('Expected driver already selected; device problem '+$dev.ConfigManagerErrorCode+'. Reinstalling it repeatedly will not fix its boot or hardware state.')}}
  $script:ComponentState='already-installed';Note ($Component.Name+': the expected driver is already selected and device status is 0.');return
 }
 $backup=Join-Path $PackRoot ('backup-'+$Component.Name)
 if(Test-Path -LiteralPath $backup){throw 'This session already attempted the component. Close and rerun the EXE for a new verified session.'}
 $i=0;foreach($dev in $devices){BackupDevice $dev (Join-Path $backup ('device-'+$i));$i++}
 try {
  $reboot=$false;$targets=@()
  foreach($dev in $devices){
   $target=[Windows7DriverApi]::InstallationTarget($dev,$Component.HardwareID)
   Note ('Matched '+$dev.PNPDeviceID+' using '+$Component.HardwareID+'; installation target '+$target)
   if($targets -notcontains $target){$targets+=$target;if([Windows7DriverApi]::Install([IntPtr]::Zero,$target,$inf)){$reboot=$true}}
  }
  if($reboot){$script:RebootNeeded=$true;$script:ComponentState='restart-required'}
  $after=@(Present $Component.HardwareID);$after|Export-Clixml -Path (Join-Path $backup 'devices-after.xml')
  if(!$after.Length){throw 'Device disappeared during installation; completion cannot be verified.'}
  foreach($dev in $after){
   Note ('  '+$dev.Name+': device status '+$dev.ConfigManagerErrorCode+'; service '+$dev.Service)
   if((InstalledINF $dev) -ne (Hash $inf)){throw 'Windows did not select the supplied driver INF. The existing driver was retained; no forced replacement was used.'}
   if($dev.ConfigManagerErrorCode -ne 0 -and !($reboot -and $dev.ConfigManagerErrorCode -eq 14) -and !($script:GraphicsBootRepaired -and $Component.Name-eq'AMD-M370X' -and $dev.ConfigManagerErrorCode-eq43)){throw ('Driver is registered but device reports problem code '+$dev.ConfigManagerErrorCode)}
  }
  Note ($Component.Name+': installed INF verified; restart required='+$reboot+'. Physical functions still require testing.')
 } catch {
  $_|Out-String|Out-File -FilePath (Join-Path $backup 'failure.txt') -Encoding utf8
  throw
 } finally {
  if(Test-Path -LiteralPath "$env:SystemRoot\inf\setupapi.dev.log"){[IO.File]::Copy("$env:SystemRoot\inf\setupapi.dev.log",(Join-Path $backup 'setupapi-after.log'),$true)}
 }
}
function InstallSigningUpdate {
 $packages='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
 $installed=@(Get-ChildItem -LiteralPath $packages|Where-Object {$_.PSChildName -match '^Package_for_KB(3033929|4474419)[_~]' }|Where-Object {(Get-ItemProperty -LiteralPath $_.PSPath).CurrentState -eq 112})
 if($installed.Count){Note 'SHA-2 support update is already recorded.';return}
 $msu=Original 'Payload\Microsoft-SHA2-Update\Windows6.1-KB3033929-x64.msu'
 Note 'Installing the original Microsoft SHA-2 update. Windows servicing may take several minutes.'
 $process=Start-Process -FilePath "$env:SystemRoot\System32\wusa.exe" -ArgumentList ('"'+$msu+'" /quiet /norestart') -WindowStyle Hidden -PassThru -Wait
 $process.ExitCode|Out-File -FilePath (Join-Path $PackRoot 'sha2-servicing-exit.txt') -Encoding ascii
 # WUSA success/already installed; 3010 means do not attempt drivers until the
 # owner's ordinary reboot. Never create an elevated persistence task.
 if($process.ExitCode -eq 3010){$script:RebootNeeded=$true;$script:ComponentState='restart-required';Note 'Signing prerequisite installed. Restart Windows before continuing driver installation.';return}
 if($process.ExitCode -ne 0 -and $process.ExitCode -ne 2359302){throw ('Microsoft update did not complete: '+$process.ExitCode)}
 if(Test-Path -LiteralPath "$env:SystemRoot\winsxs\pending.xml"){$script:RebootNeeded=$true;$script:ComponentState='restart-required';Note 'Windows servicing requires a restart before drivers can be installed.';return}
 Note 'Microsoft update completed; no signing-policy change.'
}
function InstallTrackpad {
 $devices=@(Present 'USB\VID_05AC&PID_0274&MI_02')
 if($devices.Length -ne 1){throw 'Expected one supported Apple trackpad interface; no filter changed.'}
 $dev=$devices[0];$id=$dev.PNPDeviceID;$key='HKLM:\SYSTEM\CurrentControlSet\Enum\'+$id
 $source=Original 'Payload\Apple-Trackpad\AppleMTP.sys'
 $inf=Original 'Payload\Apple-Trackpad\AppleMTP64.inf'
 $cat=Original 'Payload\Apple-Trackpad\AppleMTP64.cat';[void](Trusted $cat)
 foreach($item in @(@($source,'6B2F843AE6CA1069F020A8DEFD683251C339A63AEE8AB5179D416EDA7C1EE54C'),@($inf,'29216B4C8DAFBA55FF4D6635A4BE1F58E78402309817C0D8736E86262D2B07EC'))){
  if([Windows7DriverApi]::VerifyMember($cat,$item[0],$item[1]) -ne 0){throw 'Original Apple trackpad catalog-member validation failed.'}
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
 $catName='windows7-applemtp-'+[Guid]::NewGuid().ToString()+'.cat'
 $catPath=$null;$fileCopied=$false;$serviceCreated=$false;$filterApplied=$false
 try {
  $catPath=[Windows7DriverApi]::Catalog($cat,$catName,$false)
  if((Hash $catPath) -ne (Hash $cat)){throw 'Registered catalog readback failed'}
  [IO.File]::Copy($source,$destination,$false);$fileCopied=$true
  if((Hash $destination) -ne (Hash $source)){throw 'Trackpad driver readback failed'}
  & "$env:SystemRoot\System32\sc.exe" create applemtp type= kernel start= demand error= normal binPath= '\SystemRoot\System32\drivers\AppleMTP.sys' DisplayName= 'Apple Multi-Touch'|Out-Null
  if($LASTEXITCODE -ne 0){throw 'Trackpad service creation failed'};$serviceCreated=$true
  & "$env:SystemRoot\System32\sc.exe" description applemtp 'Windows7 verified Apple trackpad package 1'|Out-Null
  if($LASTEXITCODE -ne 0){throw 'Trackpad service receipt failed'}
  [void](New-ItemProperty -LiteralPath $svc -Name HotspringTrackpads -PropertyType MultiString -Value @('VID_05AC&PID_0273','VID_05AC&PID_0274','VID_05AC&PID_0290','VID_05AC&PID_0291'))
  [void](New-Item -Path ($svc+'\Parameters\Wdf') -Force)
  [void](New-ItemProperty -LiteralPath ($svc+'\Parameters\Wdf') -Name KmdfLibraryVersion -PropertyType String -Value '1.11')
  [Windows7DriverApi]::SetLowerFilters($id,[string[]]@('applemtp'));$filterApplied=$true
  if([Windows7DriverApi]::Restart($id)){$script:RebootNeeded=$true}
  @(Present 'USB\VID_05AC&PID_0274&MI_02')|Export-Clixml -Path (Join-Path $backup 'device-after.xml')
  $driver=New-Object System.ServiceProcess.ServiceController('applemtp')
  $driver.Status.ToString()|Out-File -FilePath (Join-Path $backup 'driver-after.txt') -Encoding utf8
  if(!$script:RebootNeeded -and $driver.Status.ToString() -ne 'Running'){throw 'Trackpad filter did not start'}
  New-Object PSObject -Property @{Device=$id;Catalog=$catPath;Driver=$destination;SHA256=(Hash $source);BeforeLowerFilters=@();OriginalServiceAbsent=$true}|Export-Clixml -Path (Join-Path $backup 'owned-changes.xml')
  Note 'Original Apple trackpad filter attached. Use Boot Camp Control Panel to enable tapping, secondary click and scrolling. No global mouse/keyboard filter changed.'
 } catch {
  $originalFailure=$_;$_|Out-String|Out-File -FilePath (Join-Path $backup 'failure.txt') -Encoding utf8
  try {
   if($filterApplied){$now=@((Get-ItemProperty -LiteralPath $key).LowerFilters|Where-Object {$_});if($now.Count -ne 1 -or $now[0] -ne 'applemtp'){throw 'Filter changed since installation; not overwriting it.'};[Windows7DriverApi]::SetLowerFilters($id,[string[]]@());if([Windows7DriverApi]::Restart($id)){$script:RebootNeeded=$true}}
   $driver=New-Object System.ServiceProcess.ServiceController('applemtp')
   if($serviceCreated -and $driver.Status.ToString() -eq 'Running'){throw 'Basic input restored; the filter is still loaded. Restart before any owned-file cleanup.'}
   if($serviceCreated){& "$env:SystemRoot\System32\sc.exe" delete applemtp|Out-Null;if($LASTEXITCODE -ne 0){throw 'Service rollback failed'}}
   if($fileCopied -and (Hash $destination) -eq (Hash $source)){[IO.File]::Delete($destination)}
   if($catPath -and (Hash $catPath) -eq (Hash $cat)){[void][Windows7DriverApi]::Catalog($null,$catName,$true)}
   Note 'Failed trackpad attempt rolled back to the original basic HID input.'
  } catch {$_|Out-String|Out-File -FilePath (Join-Path $backup 'rollback-attention.txt') -Encoding utf8;Note ('Rollback needs attention: '+$_)}
  throw $originalFailure
 }
}
function ControlPanelRegistryPlan([string]$RunPath,[string]$OriginalPath) {
 if(!$RunPath -or $RunPath -match '[\s"]' -or $RunPath -notmatch '^[A-Za-z]:\\.*\\Bootcamp\.exe$'){throw 'Unsafe Apple utility startup path'}
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
  @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run','Apple_KbdMgr',$RunPath,'String')
 )
 foreach($item in $items){
  $legacy=$null;if($item[1]-eq'Apple_KbdMgr' -and $OriginalPath){$legacy='"'+$OriginalPath+'"'}
  New-Object PSObject -Property @{Key=$item[0];Name=$item[1];Value=$item[2];Kind=$item[3];LegacyQuotedValue=$legacy}
 }
}
function RegistryDisposition([bool]$Exists,$Value,[string]$Kind,$Expected) {
 if(!$Exists){return 'missing'}
 if($Value -eq $Expected.Value -and $Kind -eq $Expected.Kind){return 'retain'}
 if($Expected.Name-eq'Apple_KbdMgr' -and $Expected.Key-eq'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -and $Expected.LegacyQuotedValue -and $Value-eq$Expected.LegacyQuotedValue -and $Kind-eq'String'){return 'repair-quoted'}
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
 $backup=Join-Path $PackRoot 'backup-BootCamp-ControlPanel'
 if(Test-Path -LiteralPath $backup){throw 'Rerun the EXE for a new verified session before retrying this component.'}
 [void][IO.Directory]::CreateDirectory($backup)
 $map=@(@($exe,(Join-Path $folder 'Bootcamp.exe')),@($resource,(Join-Path $folder 'Boot Camp.Resources\en.lproj\Resources.dll')),@($panel,$targetPanel))
 foreach($pair in $map){if((Test-Path -LiteralPath $pair[1]) -and (Hash $pair[1]) -ne (Hash $pair[0]) -and !($ExpectedModel-eq'MacBookPro11,5'-and$pair[1]-eq(Join-Path $folder 'Bootcamp.exe')-and(Hash $pair[1])-eq'97051c55d0155197b02060a7f10323464c7954f09660ef9ecb346b60be7a0eb2')){throw ('Different existing Boot Camp file retained: '+$pair[1])}}
 New-Object PSObject -Property @{Files=$map}|Export-Clixml -Path (Join-Path $backup 'before-files.xml')
 $ownedFiles=@();$ownedValues=@();$repairedValues=@()
 try {
  foreach($pair in $map){
   if(!(Test-Path -LiteralPath $pair[1])){
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($pair[1]))
    [IO.File]::Copy($pair[0],$pair[1],$false);$ownedFiles+=,$pair
    $ownedFiles|Export-Clixml -Path (Join-Path $backup 'created-files.xml')
   }
   if((Hash $pair[1]) -ne (Hash $pair[0]) -and !($ExpectedModel-eq'MacBookPro11,5'-and$pair[1]-eq(Join-Path $folder 'Bootcamp.exe')-and(Hash $pair[1])-eq'97051c55d0155197b02060a7f10323464c7954f09660ef9ecb346b60be7a0eb2')){throw 'Boot Camp file verification failed'}
  }
  $runPath=[Windows7DriverApi]::ResourceSafeExecutablePath($map[0][1])
  $derivedResource=Join-Path ([IO.Path]::GetDirectoryName($runPath)) 'Boot Camp.Resources\en.lproj\Resources.dll'
  if((Hash $runPath)-ne(Hash $map[0][1]) -or (Hash $derivedResource)-ne(Hash $resource)){throw 'Apple startup resource lookup failed validation'}
  $plan=@(ControlPanelRegistryPlan $runPath $map[0][1])
  $before=@();foreach($entry in $plan){$before+=New-Object PSObject -Property @{Entry=$entry;State=(ReadPlannedRegistry $entry)}}
  New-Object PSObject -Property @{Files=$map;Registry=$before}|Export-Clixml -Path (Join-Path $backup 'before.xml')
  foreach($entry in $plan){
   $state=ReadPlannedRegistry $entry
   if($state -eq 'retain'){continue}
   $key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($entry.Key)
   try {
    if($state-eq'repair-quoted'){
     if((ReadPlannedRegistry $entry)-ne'repair-quoted'){throw 'Legacy startup value changed during repair'}
     $repairedValues+=,$entry;$repairedValues|Export-Clixml -Path (Join-Path $backup 'repaired-values.xml')
    }elseif(@($key.GetValueNames()) -contains $entry.Name){throw 'Registry changed during installation; no existing value overwritten.'}
    $key.SetValue($entry.Name,$entry.Value,[Enum]::Parse([Microsoft.Win32.RegistryValueKind],$entry.Kind))
    if($state-ne'repair-quoted'){$ownedValues+=,$entry;$ownedValues|Export-Clixml -Path (Join-Path $backup 'created-values.xml')}
   }finally{$key.Close()}
   if((ReadPlannedRegistry $entry) -ne 'retain'){throw 'Boot Camp registration readback failed'}
  }
 } catch {
  $originalFailure=$_;$failures=@()
  foreach($entry in $repairedValues){
   try {
    if((ReadPlannedRegistry $entry)-eq'retain'){
     $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($entry.Key,$true)
     try{$key.SetValue($entry.Name,$entry.LegacyQuotedValue,[Microsoft.Win32.RegistryValueKind]::String)}finally{$key.Close()}
    }
   }catch{$failures+=$_.ToString()}
  }
  for($i=$ownedValues.Count-1;$i -ge 0;$i--){
   $entry=$ownedValues[$i]
   try {
    if((ReadPlannedRegistry $entry) -eq 'retain'){
     $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($entry.Key,$true)
     try {$key.DeleteValue($entry.Name,$false)}finally{$key.Close()}
    }
   }catch{$failures+=$_.ToString()}
  }
  foreach($pair in $ownedFiles){try {if(Test-Path -LiteralPath $pair[1]){if((Hash $pair[1]) -ne (Hash $pair[0]) -and !($ExpectedModel-eq'MacBookPro11,5'-and$pair[1]-eq(Join-Path $folder 'Bootcamp.exe')-and(Hash $pair[1])-eq'97051c55d0155197b02060a7f10323464c7954f09660ef9ecb346b60be7a0eb2')){throw ('Created file changed; retained '+$pair[1])};[IO.File]::Delete($pair[1])}}catch{$failures+=$_.ToString()}}
  @('Only values/files created by this attempt were considered for rollback. Existing registrations and empty keys/directories were retained.')+$failures|Out-File -FilePath (Join-Path $backup 'rollback.txt') -Encoding utf8
  throw $originalFailure
 }
 'Original Boot Camp tray starts with normal user privileges at the next sign-in. No elevated task/service was installed. Open Control Panel > Boot Camp for trackpad options.'|Out-File -FilePath (Join-Path $backup 'result.txt') -Encoding utf8
 Note 'Boot Camp Control Panel and normal-user tray startup installed. The tray appears at the next sign-in; this installer does not launch it as administrator.'
}
function Components([string]$Model) {
 $items=@(
  @{Name='Microsoft-SHA2-Update';Title='Microsoft SHA-2 signing support (restart may be needed)';Kind='Update'},
  @{Name='Graphics-Boot';Title='Verify the installed model-specific graphics boot path';Kind='GraphicsBoot'},
  @{Name='BootCamp-Dependencies';Title='Original Apple Fn and keyboard-backlight services';Kind='AppleDependencies'},
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
 if($Model -eq 'MacBookPro11,4'){$items+=@(
  @{Name='Intel-Iris';Title='Intel Iris Pro 5200 graphics';Kind='INF';HardwareID='PCI\VEN_8086&DEV_0D26';Inf='Payload\Intel-Iris\igdlh64.inf';Catalog='Payload\Intel-Iris\igdlh.cat'},
  @{Name='Intel-HDMI-Audio';Title='Intel HDMI display audio';Kind='INF';HardwareID='HDAUDIO\FUNC_01&VEN_8086&DEV_2807';Inf='Payload\Intel-HDMI-Audio\IntcDAud.inf';Catalog='Payload\Intel-HDMI-Audio\IntcDAud.cat'}
 )}
 foreach($id in @('ACPI\APP0001','ACPI\APP0002','ACPI\APP000B')){$items+=@{Name=('Apple-Identification-'+$id.Split('\')[-1]);Title=('Apple hardware identification '+$id);Kind='INF';HardwareID=$id;Inf='Payload\Apple-Identification\AppleNull64.inf';Catalog='Payload\Apple-Identification\AppleNull64.cat'}}
 foreach($row in @(@('8C22','SMBus'),@('8C24','Thermal'))){$items+=@{Name=('Intel-Identification-'+$row[1]);Title=('Intel '+$row[1]+' identification');Kind='INF';HardwareID=('PCI\VEN_8086&DEV_'+$row[0]);Inf=('Payload\Intel-Identification\Chipset_'+$row[1]+'.inf');Catalog='Payload\Intel-Identification\Chipset.cat'}}
 if($Model-eq'MacBookPro11,5'){$items+=@{Name='Apple-Thunderbolt-Identification';Title='Apple Thunderbolt identification (not Ethernet repair)';Kind='INF';HardwareID='PCI\VEN_8086&DEV_156C&CC_0880';Inf='Payload\Apple-Identification\AppleNull64.inf';Catalog='Payload\Apple-Identification\AppleNull64.cat'}}
 $items+=@(@{Name='Apple-Trackpad';Title='Apple trackpad (Boot Camp options)';Kind='Trackpad'},@{Name='BootCamp-ControlPanel';Title='Boot Camp Control Panel and tray utility';Kind='ControlPanel'},@{Name='Apple-Keyboard-Layouts';Title='Apple keyboard layouts (automatically selected for your keyboard language)';Kind='KeyboardLayouts'})
 $items+=@(@{Name='Trackpad-Startup';Title='Automatic trackpad scrolling';Kind='TrackpadStartup'},@{Name='Backlight-Response';Title='Keyboard-backlight response';Kind='Backlight'})
 return $items
}
function InstallKeyboardLayouts {
 # Machine registration is elevated; the wizard then applies the preference
 # as its ORIGINAL user, including when UAC used another admin's credentials.
 & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $PackRoot 'Apple-Keyboard-Layout.ps1') -Mode Register -PackRoot $PackRoot
 if($LASTEXITCODE-ne0){throw 'Original Apple keyboard layout installation failed'}
 Note 'Original Apple keyboard layouts registered. Setup will automatically select the matching layout for the signed-in user.'
}

function RunPlan($Plan,[scriptblock]$Runner) {
 $script:Results=@();$script:RebootNeeded=$false;$number=0
 foreach($component in $Plan){
  $number++;$script:ComponentState='installed';$detail=''
  Note ('W7DEP_PROGRESS|'+($number-1)+'|'+$Plan.Count+'|'+$component.Title)
  try {& $Runner $component} catch {
   $script:ComponentState='failed';$detail=$_.ToString()
   Note ('FAILED '+$component.Title+': '+$detail)
   if($PackRoot){($_|Format-List * -Force|Out-String)|Out-File -FilePath (Join-Path $PackRoot ($component.Name+'-error.txt')) -Encoding utf8}
  }
  $script:Results+=New-Object PSObject -Property @{Name=$component.Name;Title=$component.Title;State=$script:ComponentState;Detail=$detail}
  if($PackRoot){$script:Results|Export-Clixml -Path (Join-Path $PackRoot 'component-results.xml')}
  # The signing prerequisite is the only mandatory mid-sequence boundary.
  # A display-driver restart request does NOT skip HDMI, trackpad or the tray.
  if($component.Kind -eq 'Update' -and ($script:RebootNeeded -or $script:ComponentState -eq 'failed')){break}
 }
 foreach($row in $script:Results){Note ($row.Title+': '+$row.State)}
 if($script:RebootNeeded){return 3010}
 if(@($script:Results|Where-Object {$_.State -eq 'failed' -or $_.State -eq 'not-detected'}).Count){return 2}
 return 0
}

. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Apple-Timestamp-Trust.ps1')
. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Accepted-Hardware.ps1')
. (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Repair-Graphics-Boot.ps1')

if($SelfTest){
 foreach($bad in @('','..\x','x\..\y','C:\x','\server\x','x:ads','x\\y','x\')){$threw=$false;try{[void](Relative $bad)}catch{$threw=$true};if(!$threw){throw 'Path test failed'}}
 if((Relative 'Payload\Apple-Keyboard\Keymagic.sys') -ne 'Payload\Apple-Keyboard\Keymagic.sys'){throw 'Valid relative path rejected'}
 if(@(Components 'MacBookPro11,4'|Where-Object {$_.Name -like 'AMD-*'}).Count){throw '11,4 AMD exclusion failed'}
 if(@(Components 'MacBookPro11,5'|Where-Object {$_.Name -like 'AMD-*'}).Count -ne 2){throw '11,5 AMD components missing'}
 foreach($m in @('MacBookPro11,4','MacBookPro11,5')){if(@(Components $m|Where-Object {$_.Kind-eq'KeyboardLayouts'}).Count-ne1){throw 'Automatic Apple keyboard layout stage missing'}}
 $panelPlan=@(ControlPanelRegistryPlan 'C:\PROGRA~1\BOOTCA~1\Bootcamp.exe' 'C:\Program Files\Boot Camp\Bootcamp.exe')
 if($panelPlan.Count -ne 9){throw 'Control panel registration plan incomplete'}
 foreach($entry in $panelPlan){
  if((RegistryDisposition $false $null '' $entry) -ne 'missing'){throw 'Missing registration test failed'}
  if((RegistryDisposition $true $entry.Value $entry.Kind $entry) -ne 'retain'){throw 'Idempotent registration test failed'}
  $threw=$false;try{[void](RegistryDisposition $true 'Unrelated existing value' $entry.Kind $entry)}catch{$threw=$true};if(!$threw){throw 'Existing registration protection failed'}
 }
 $runEntry=@($panelPlan|Where-Object {$_.Name-eq'Apple_KbdMgr'})[0]
 if((RegistryDisposition $true '"C:\Program Files\Boot Camp\Bootcamp.exe"' 'String' $runEntry)-ne'repair-quoted'){throw 'Quoted legacy Run repair test failed'}
 foreach($badRun in @('"C:\Program Files\Boot Camp\Bootcamp.exe"','C:\Program Files\Boot Camp\Bootcamp.exe','C:\PROGRA~1\BOOTCA~1\Bootcamp.exe /extra')){
  $threw=$false;try{[void](ControlPanelRegistryPlan $badRun '')}catch{$threw=$true};if(!$threw){throw 'Unsafe startup path accepted'}
 }
 Add-Type -Path (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'Native-Driver-Api.cs')
 if(![Windows7DriverApi]::LayoutSelfTest() -or ![Windows7DriverApi]::PropertyReaderSelfTest()){throw 'Native structure/property query self-test failed'}
 foreach($id in @('PCI\VEN_14E4&DEV_43BA','PCI\VEN_8086&DEV_8C3A')){
  $dev=New-Object Windows7DriverApi+DeviceInfo
  $dev.HardwareID=[string[]]@(($id+'&SUBSYS_12345678&REV_01'),($id+'&CC_0280'));$dev.CompatibleID=[string[]]@($id)
  if(![Windows7DriverApi]::Matches($dev,$id.ToLowerInvariant())){throw 'Compatible-ID matching regression'}
  if([Windows7DriverApi]::InstallationTarget($dev,$id) -ne $dev.HardwareID[0]){throw 'Installation target must be a hardware ID'}
  if([Windows7DriverApi]::Matches($dev,($id+'0'))){throw 'Partial-ID matches must not be accepted'}
 }
 $plan=@(@{Name='GPU';Title='GPU';Kind='INF'},@{Name='HDMI';Title='HDMI';Kind='INF'},@{Name='Panel';Title='Panel';Kind='ControlPanel'})
 $script:Seen=@();$code=RunPlan $plan {param($c);$script:Seen+=$c.Name;if($c.Name -eq 'GPU'){$script:RebootNeeded=$true}}
 if($code -ne 3010 -or $script:Seen.Count -ne 3){throw 'GPU restart incorrectly skipped remaining drivers'}
 $script:Seen=@();$code=RunPlan $plan {param($c);$script:Seen+=$c.Name;if($c.Name -eq 'GPU'){throw 'fixture failure'}}
 if($code -ne 2 -or $script:Seen.Count -ne 3){throw 'Independent components must still run after a failure'}
 $script:Seen=@();$code=RunPlan @(@{Name='SHA2';Title='SHA2';Kind='Update'},@{Name='After';Title='After';Kind='INF'}) {param($c);$script:Seen+=$c.Name;$script:RebootNeeded=$true}
 if($code -ne 3010 -or $script:Seen.Count -ne 1){throw 'Signing update restart handling failed'}
 'PASS: pure policy/path tests and read-only native ABI checks. No driver, registry, UAC or device changes.';exit 0
}

try {
 if([IntPtr]::Size -ne 8 -or [Environment]::OSVersion.Version.ToString() -notlike '6.1.7601*'){throw 'Windows 7 SP1 x64 only'}
 if(!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Use the EXE and approve normal Windows UAC.'}
 # The native engine verifies the real SMBIOS model before staging. Avoid a
 # second WMI dependency on a newly installed Windows instance.
 $model=$ExpectedModel
 if(@('MacBookPro11,5','MacBookPro11,4') -notcontains $model){throw 'Unsupported model'}
 $PackRoot=[IO.Path]::GetFullPath($PackRoot)
 if([IO.Path]::GetDirectoryName($PackRoot) -ne [Environment]::GetFolderPath('CommonApplicationData') -or [IO.Path]::GetFileName($PackRoot) -notlike 'Windows7-Driver-Setup-{*}'){throw 'Use the EXE-created protected staging directory.'}
 if((Get-Item -LiteralPath $PackRoot).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Staging cannot be a link'}
 $script:Inventory=@(Import-Csv -Path (Join-Path $PackRoot 'expected-files.csv'))
 foreach($row in $script:Inventory){if(($row.AMD -eq '1' -and $model -eq 'MacBookPro11,4') -or ($row.AMD -eq '2' -and $model -eq 'MacBookPro11,5')){continue};[void](Original $row.Path)}
 Add-Type -Path (Join-Path $PackRoot 'Native-Driver-Api.cs')
 if(![Windows7DriverApi]::LayoutSelfTest()){throw 'Native API layout mismatch'}
 Add-Type -AssemblyName System.ServiceProcess
 Note ('Driver setup 0.3.0; Windows '+[Environment]::OSVersion.Version+'; CLR '+[Environment]::Version+'. Reading present-device properties using size-probed native queries.')
 $deviceSnapshot=[Windows7DriverApi]::Devices()
 $deviceSnapshot|Export-Clixml -Path (Join-Path $PackRoot 'devices-before.xml')
 $ids=0;foreach($device in $deviceSnapshot){$ids+=$device.HardwareID.Length}
 Note ('Device inventory: '+$deviceSnapshot.Length+' present devices, '+$ids+' hardware IDs. Saved devices-before.xml.')
 if($deviceSnapshot.Length -eq 0 -or $ids -eq 0){throw 'Hardware inventory is empty; no driver changes will be attempted.'}
 Note ('Installing all applicable components for '+$model+'. No WMI dependency, no security-policy changes.')
 if(Test-Path -LiteralPath "$env:SystemRoot\winsxs\pending.xml"){Note 'Windows servicing is pending. Restart before continuing.';exit 3010}
 $code=RunPlan @(Components $model) {param($component)
  Note ('Starting '+$component.Title)
  switch($component.Kind){'Update'{InstallSigningUpdate};'INF'{InstallINF $component};'Trackpad'{InstallTrackpad};'ControlPanel'{InstallControlPanel};'KeyboardLayouts'{InstallKeyboardLayouts};'GraphicsBoot'{RepairGraphicsBoot};'AppleDependencies'{InstallAppleDependencies};'TrackpadStartup'{InstallTrackpadStartup};'Backlight'{InstallBacklightResponse};default{throw 'Unknown component'}}
 }
 Note 'Enable your preferred trackpad options in Boot Camp Control Panel after signing in.'
 Note 'Camera, sleep/resume and dock Ethernet remain deferred. No fan, power or default-boot settings changed.'
 Note ('Logs and rollback records: '+$PackRoot)
 exit $code
} catch {
 if($PackRoot -and (Test-Path -LiteralPath $PackRoot)){($_|Format-List * -Force|Out-String)|Out-File -FilePath (Join-Path $PackRoot 'fatal-error.txt') -Encoding utf8;Note ('FAILED: '+$_.ToString())}
 [Console]::WriteLine('FAILED: '+$_.ToString());exit 1
}
