# Embedded installer functions, Windows 7 SP1 / PowerShell 2 compatible.
# Dot-source only from the verified protected setup session.
function InstallAppleDependencies {
 $sources=@{}
 foreach($name in @('MacHALDriver','KeyAgent')){$sources[$name]=Original ('Payload\BootCamp-Dependencies\'+$name+'.sys')}
 EnsureAppleTimestampTrust @($sources.Values)
 foreach($name in @('MacHALDriver','KeyAgent')){
  [void](Trusted $sources[$name])
  $key='HKLM:\SYSTEM\CurrentControlSet\Services\'+$name
  $dest="$env:WINDIR\System32\drivers\"+$name+'.sys'
  $image='\SystemRoot\System32\drivers\'+$name+'.sys'
  $start=2;$mode='auto';if($name-eq'MacHALDriver'){$start=1;$mode='system'}
  if(Test-Path -LiteralPath $key){
   $v=Get-ItemProperty -LiteralPath $key
   if($v.Type-ne1-or$v.ImagePath-ne$image-or$v.Start-ne$start-or!(Test-Path -LiteralPath $dest)-or(Hash $dest)-ne(Hash $sources[$name])){throw ('Existing Apple service differs; retained: '+$name)}
   Note ($name+': expected original service already installed.');continue
  }
  if(Test-Path -LiteralPath $dest){throw ('Unowned driver file retained: '+$dest)}
  $backup=Join-Path $PackRoot ('backup-'+$name);[void][IO.Directory]::CreateDirectory($backup)
  ('Service and destination absent. Creating only '+$name+' from verified original publisher bytes; startup='+$mode+'. Rollback: disable only this service, reboot, then remove service/file only if hashes still match.')|Out-File (Join-Path $backup 'before-and-rollback.txt')
  [IO.File]::Copy($sources[$name],$dest,$false)
  if((Hash $dest)-ne(Hash $sources[$name])){throw 'Apple service copy verification failed'}
  & "$env:WINDIR\System32\sc.exe" create $name type= kernel start= $mode error= normal binPath= $image DisplayName= $name | Out-Null
  if($LASTEXITCODE-ne0){throw ('Original Apple service creation failed: '+$name)}
  if((Get-ItemProperty -LiteralPath $key).Start-ne$start){throw 'Apple startup readback failed'}
  # Load in the original MSI order at normal restart, not by replacing active input.
  $script:RebootNeeded=$true
 }
}

function InstallTrackpadStartup {
 $source=Join-Path $PackRoot 'BackToSeven-Trackpad-Preferences.exe'
 if((Hash $source)-ne'7077e492368cfac6e1c86aeceee5c0806bfb3bb1990176f6e8e1f1964be594b0'){throw 'Trackpad helper hash mismatch'}
 $folder=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'BackToSeven\Trackpad-Preferences'
 $dest=Join-Path $folder 'BackToSeven-Trackpad-Preferences.exe'
 $key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';$name='BackToSeven Trackpad Preferences';$value='"'+$dest+'"'
 $old=(Get-ItemProperty -LiteralPath $key).PSObject.Properties[$name]
 if($old-and$old.Value-ne$value){throw 'Unrelated trackpad startup entry retained'}
 if((Test-Path -LiteralPath $dest)-and(Hash $dest)-ne(Hash $source)){throw 'Different trackpad helper retained'}
 [void][IO.Directory]::CreateDirectory($folder)
 if(!(Test-Path -LiteralPath $dest)){[IO.File]::Copy($source,$dest,$false)}
 if((Hash $dest)-ne(Hash $source)){throw 'Trackpad helper copy verification failed'}
 if(!$old){New-ItemProperty -LiteralPath $key -Name $name -Value $value -PropertyType String | Out-Null}
 if((Get-ItemProperty -LiteralPath $key).PSObject.Properties[$name].Value-ne$value){throw 'Trackpad startup verification failed'}
 # The wizard applies per-user preferences with the original user's token.
 [IO.File]::WriteAllText((Join-Path $PackRoot 'trackpad-settings-ready.txt'),$dest)
 Note 'Normal-user trackpad startup installed; scrolling preferences will be applied for the original signed-in user.'
}

function InstallBacklightResponse {
 if($ExpectedModel-ne'MacBookPro11,5'){Note '11,4 retains the original responsive Apple utility.';return}
 & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File (Join-Path $PackRoot 'BootCamp-Backlight-Response.ps1') -Mode Apply
 if($LASTEXITCODE-ne0){throw '11,5 user-mode keyboard-backlight correction failed'}
 Note '11,5 keyboard-backlight response correction verified. Original backup preserved; kernel-driver signatures unchanged.'
}
