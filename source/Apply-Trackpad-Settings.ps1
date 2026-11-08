param([string]$SessionRoot)
$ErrorActionPreference='Stop'
if([Environment]::OSVersion.Version.ToString()-notlike'6.1.7601*'){throw 'Windows 7 SP1 only'}
$root=[IO.Path]::GetFullPath($SessionRoot)
if([IO.Path]::GetDirectoryName($root)-ne[Environment]::GetFolderPath('CommonApplicationData')-or[IO.Path]::GetFileName($root)-notlike'Windows7-Driver-Setup-{*}'){throw 'Unexpected session'}
if(!(Test-Path -LiteralPath (Join-Path $root 'trackpad-settings-ready.txt'))){throw 'Trackpad setup did not complete'}
$key='HKCU:\Software\Apple Inc.\Trackpad'
$log=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'BackToSeven'
[void][IO.Directory]::CreateDirectory($log)
if(Test-Path -LiteralPath $key){
 & "$env:WINDIR\System32\reg.exe" export 'HKCU\Software\Apple Inc.\Trackpad' (Join-Path $log ('Trackpad-before-'+[Guid]::NewGuid().ToString()+'.reg')) /y | Out-Null
 if($LASTEXITCODE-ne0){throw 'Trackpad preferences backup failed'}
}
# Accepted default 43: tap/drag and two-finger secondary click, scrolling enabled.
# Apple Control Panel remains available for later personal preference changes.
if(!(Test-Path -LiteralPath $key)){New-Item -Path $key -Force | Out-Null}
New-ItemProperty -LiteralPath $key -Name Mode -Value 43 -PropertyType DWord -Force | Out-Null
if((Get-ItemProperty -LiteralPath $key).Mode-ne43){throw 'Trackpad preference readback failed'}
'Trackpad preferences set for the original user. The normal-user startup helper reapplies them at sign-in.'
