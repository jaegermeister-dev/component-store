; Standard Windows wizard. The engine and payload remain model-filtered and
; hash pinned. No Windows driver is redistributed inside this small EXE.
#ifndef Engine
  #error Engine is required
#endif
#ifndef BuildOutput
  #error BuildOutput is required
#endif
[Setup]
AppId=Windows7-Community-Windows7-Drivers
AppName=BackToSeven Drivers Installer
AppVersion=0.3.3
AppPublisher=jaegermeister-dev
DefaultDirName={autopf}\Windows7
CreateAppDir=no
Uninstallable=no
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableWelcomePage=no
#ifdef Preview
PrivilegesRequired=lowest
#else
PrivilegesRequired=admin
#endif
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=6.1sp1
#ifndef Preview
OnlyBelowVersion=6.2
#endif
WizardStyle=modern
SetupIconFile=BackToSeven.ico
WizardImageFile=BackToSeven-Wizard.bmp
WizardSmallImageFile=BackToSeven-Wizard-Small.bmp
WizardImageStretch=yes
WizardSizePercent=112
WizardResizable=yes
SetupLogging=yes
AllowCancelDuringInstall=no
CloseApplications=no
RestartApplications=no
OutputDir={#BuildOutput}
#ifdef Preview
OutputBaseFilename=Driver-Wizard-Preview
#else
OutputBaseFilename=BackToSeven Drivers Installer
#endif
Compression=lzma2
SolidCompression=yes
VersionInfoDescription=BackToSeven Drivers Installer
[Files]
Source: "{#Engine}"; DestName: "Windows7-Driver-Engine.exe"; Flags: dontcopy notimestamp
[Messages]
WelcomeLabel1=Welcome to BackToSeven
WelcomeLabel2=BackToSeven Drivers Installer prepares your Mac for Windows 7.%n%nThis wizard installs the applicable Windows 7 drivers and Boot Camp Control Panel for your Mac.%n%nThe driver files were prepared by the macOS installation app. No Internet connection is needed in Windows.%n%nSetup may need to restart Windows before finishing. Normal administrator approval and Windows driver-signature checks remain enabled.
ReadyLabel1=Setup is ready to install the applicable drivers.
ReadyLabel2a=Click Install to begin. There is no need to select or install individual driver packages.
FinishedHeadingLabel=Driver setup results
[Code]
var
  Details: TNewMemo;
  ViewLog: TNewButton;
  SessionRoot, PayloadRoot: String;
  EngineCode, ResumeCount, FailedStages: Integer;
  RestartRequired, ResumeRegistered, EngineRan, ResultReceived, RepairMode: Boolean;
  ResultText, PlanText: String;

procedure UpdateRestartButton(Sender: TObject);
begin
  if RestartRequired and WizardForm.YesRadio.Checked then
    WizardForm.NextButton.Caption := 'Restart now'
  else WizardForm.NextButton.Caption := 'Finish';
end;

procedure OpenResults(Sender: TObject);
var
  Path: String;
  Code: Integer;
begin
  Path := AddBackslash(SessionRoot) + 'setup.log';
  if not FileExists(Path) then Path := ExpandConstant('{log}');
  if FileExists(Path) then ExecAsOriginalUser(ExpandConstant('{sys}\notepad.exe'),
    '"' + Path + '"', '', SW_SHOWNORMAL, ewNoWait, Code);
end;

procedure EngineLog(const S: String; const Error, FirstLine: Boolean);
var
  Parts: TArrayOfString;
  Current, Total: Integer;
begin
  Log(S);
  if Error then begin
    Details.Lines.Add('Output capture error: ' + S);
    Exit;
  end;
  if Pos('W7DEP_SESSION|', S) = 1 then begin
    SessionRoot := Copy(S, 15, MaxInt);
    Exit;
  end;
  if Pos('W7DEP_RESULT|', S) = 1 then begin
    Parts := StringSplit(S, ['|'], stAll);
    if GetArrayLength(Parts) = 3 then begin
      Current := StrToIntDef(Parts[1], -1);
      Total := StrToIntDef(Parts[2], -1);
      if (Current >= 0) and ((Total = 0) or (Total = 1)) then begin
        FailedStages := Current;
        ResultReceived := True;
      end;
    end;
    Exit;
  end;
  if Pos('W7DEP_PROGRESS|', S) = 1 then begin
    Parts := StringSplit(S, ['|'], stAll);
    if GetArrayLength(Parts) = 4 then begin
      Current := StrToIntDef(Parts[1], 0);
      Total := StrToIntDef(Parts[2], 0);
      if (Total > 0) and (Current >= 0) and (Current <= Total) then begin
        WizardForm.ProgressGauge.Max := Total;
        WizardForm.ProgressGauge.Position := Current;
        WizardForm.StatusLabel.Caption := Parts[3];
      end;
    end;
    Exit;
  end;
  Details.Lines.Add(S);
  WizardForm.FilenameLabel.Caption := S;
end;

procedure InitializeWizard;
var
  Counter: AnsiString;
begin
  RepairMode := ExpandConstant('{param:REPAIRGRAPHICS|0}') = '1';
  PayloadRoot := ExpandConstant('{param:RESUME|}');
  ResumeCount := 0;
  if PayloadRoot = '' then PayloadRoot := ExpandConstant('{src}')
  else if LoadStringFromFile(AddBackslash(PayloadRoot) + 'resume-count.txt', Counter) then
    ResumeCount := StrToIntDef(String(Counter), 3);
  Details := TNewMemo.Create(WizardForm);
  Details.Parent := WizardForm.InstallingPage;
  Details.Left := WizardForm.ProgressGauge.Left;
  Details.Top := WizardForm.ProgressGauge.Top + WizardForm.ProgressGauge.Height + ScaleY(12);
  Details.Width := WizardForm.ProgressGauge.Width;
  Details.Height := WizardForm.InstallingPage.ClientHeight - Details.Top - ScaleY(4);
  Details.ReadOnly := True;
  Details.ScrollBars := ssVertical;
  Details.WordWrap := True;
  ViewLog := TNewButton.Create(WizardForm);
  ViewLog.Parent := WizardForm.FinishedPage;
  ViewLog.Caption := 'View results log';
  ViewLog.Left := 0;
  ViewLog.Top := WizardForm.FinishedPage.ClientHeight - ScaleY(30);
  ViewLog.Width := ScaleX(130);
  ViewLog.Height := ScaleY(25);
  ViewLog.OnClick := @OpenResults;
  PlanText := 'Automatically detects and installs the applicable signed drivers.' + #13#10#13#10 +
    'Includes Wi-Fi, keyboard, Bluetooth, Intel Management Engine, audio, model-specific graphics and HDMI audio, trackpad and Boot Camp Control Panel.' + #13#10#13#10 +
    'Both models include Fn controls, keyboard backlight and automatic trackpad scrolling. Cameras, sleep/resume and dock Ethernet remain deferred.' + #13#10#13#10 +
    'If a restart is required, setup will offer to restart and resume after sign-in. You may need to approve UAC again.';
  if RepairMode then begin
    WizardForm.WelcomeLabel1.Caption := 'Repair graphics boot';
    WizardForm.WelcomeLabel2.Caption := 'This checks the recorded Windows 7 graphics boot path on MacBookPro11,5 and repairs only a recognised replaced entry. Drivers are not reinstalled. OpenCore, unrelated boot files and other Windows installations are preserved. A backup and results log are saved.';
    WizardForm.ReadyLabel.Caption := 'Ready to check this installation''s graphics boot path.';
    PlanText := 'Repair the known MacBookPro11,5 graphics boot route, if needed. An existing recognised multi-Windows picker is preserved. Unknown configurations are left unchanged. No driver installation, default-boot change or automatic restart.';
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
#ifndef Preview
  if (not RepairMode) and not FileExists(AddBackslash(PayloadRoot) + 'Payload\Microsoft-SHA2-Update\Windows6.1-KB3033929-x64.msu') then
    Result := 'The downloaded driver files are missing. Keep this installer beside its Payload folder, as prepared by the macOS installation app.';
#endif
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ContinueExe, ResumeExe, Engine, EngineArgs: String;
  Code, LayoutCode: Integer;
  LayoutResult: String;
begin
  if CurStep <> ssPostInstall then Exit;
#ifdef Preview
  { Compile-time developer preview: contains NO engine execution, restart or
    continuation registration. This binary is never delivered to users. }
  EngineRan := True;
  EngineCode := 0;
  EngineLog('W7DEP_PROGRESS|10|10|Driver setup complete', False, True);
  ResultText := 'PREVIEW ONLY - no drivers installed.' + #13#10#13#10 +
    'All applicable driver stages completed. Open Boot Camp Control Panel to enable your preferred trackpad options. Its tray icon starts at your next Windows sign-in.';
#else
  ExtractTemporaryFile('Windows7-Driver-Engine.exe');
  Engine := ExpandConstant('{tmp}\Windows7-Driver-Engine.exe');
  EngineCode := 1;
  EngineRan := True;
  WizardForm.StatusLabel.Caption := 'Checking hardware and driver files...';
  try
    EngineArgs := '--install';
    if RepairMode then EngineArgs := '--repair-graphics';
    if not ExecAndLogOutput(Engine, EngineArgs + ' "' + PayloadRoot + '"', PayloadRoot,
      SW_HIDE, ewWaitUntilTerminated, EngineCode, @EngineLog) then
      Details.Lines.Add('The driver engine could not start: ' + SysErrorMessage(EngineCode));
  except
    Details.Lines.Add(GetExceptionMessage);
    EngineCode := 1;
  end;
  if (EngineCode = 0) and not ResultReceived then EngineCode := 1;
  if (EngineCode = 0) and (FailedStages > 0) then EngineCode := 2;
  LayoutResult := '';
  if (not RepairMode) and (SessionRoot <> '') and FileExists(AddBackslash(SessionRoot) + 'apple-layouts-ready.txt') then begin
    Details.Lines.Add('Automatically selecting the Apple keyboard layout for your input language...');
    LayoutCode := -1;
    if not ExecAsOriginalUser(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "' +
      AddBackslash(SessionRoot) + 'Apple-Keyboard-Layout.ps1" -Mode Apply',
      SessionRoot, SW_HIDE, ewWaitUntilTerminated, LayoutCode) then LayoutCode := -1;
    if LayoutCode = 0 then
      LayoutResult := 'Apple keyboard layout installed and automatically selected. Your previous layouts remain available.'
    else begin
      LayoutResult := 'The Apple keyboard layouts are installed, but automatic selection needs attention. Check Control Panel > Region and Language > Change keyboards. Your previous layout is retained.';
      FailedStages := FailedStages + 1;
      if EngineCode = 0 then EngineCode := 2;
    end;
    Details.Lines.Add(LayoutResult);
    Log(LayoutResult + ' User-layout exit code: ' + IntToStr(LayoutCode));
  end;
  if (not RepairMode) and (SessionRoot <> '') and FileExists(AddBackslash(SessionRoot) + 'trackpad-settings-ready.txt') then begin
    LayoutCode := -1;
    if not ExecAsOriginalUser(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
      '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "' + AddBackslash(SessionRoot) +
      'Apply-Trackpad-Settings.ps1" -SessionRoot "' + SessionRoot + '"',
      SessionRoot, SW_HIDE, ewWaitUntilTerminated, LayoutCode) then LayoutCode := -1;
    if LayoutCode <> 0 then begin
      Details.Lines.Add('Automatic trackpad preferences need attention. See the saved setup log.');
      FailedStages := FailedStages + 1;
      if EngineCode = 0 then EngineCode := 2;
    end;
  end;
  RestartRequired := EngineCode = 3010;
  ResumeRegistered := False;
  if RestartRequired and not RepairMode and (ResumeCount < 3) and
    (Pos(AddBackslash(ExpandConstant('{commonappdata}')) + 'Windows7-Driver-Setup-{', SessionRoot) = 1) and
    FileExists(AddBackslash(SessionRoot) + 'expected-files.csv') then begin
    ContinueExe := AddBackslash(SessionRoot) + 'Continue-Driver-Setup.exe';
    ResumeExe := AddBackslash(SessionRoot) + 'Windows7-Resume.exe';
    if FileCopy(ExpandConstant('{srcexe}'), ContinueExe, True) and
      FileCopy(Engine, ResumeExe, True) and
      SaveStringToFile(AddBackslash(SessionRoot) + 'resume-count.txt', IntToStr(ResumeCount + 1), False) then begin
      { Register in the original user's RunOnce. Continuation requests normal
        UAC; it is NOT an elevated task/service or a security-policy change. }
      if ExecAsOriginalUser(ResumeExe, '--register-resume "' + SessionRoot + '"',
        SessionRoot, SW_HIDE, ewWaitUntilTerminated, Code) then ResumeRegistered := Code = 0;
    end;
  end;
  if RestartRequired then begin
    ResultText := 'Windows needs a restart to finish applying changes.';
    if FailedStages > 0 then ResultText := IntToStr(FailedStages) + ' driver stage(s) did not complete. A restart is also required. See View results log for details.';
    if ResumeRegistered then ResultText := ResultText + #13#10#13#10 +
      'Setup will reopen automatically after sign-in and show a UAC prompt. Approve it and click Install to continue. Do not start a second copy manually.'
    else if not RepairMode then ResultText := ResultText + #13#10#13#10 +
      'After restarting, run BackToSeven Drivers Installer.exe again. Automatic continuation is unavailable.';
  end else if EngineCode = 0 then begin
    ResultText := 'All applicable driver stages completed. Physical functions still need testing.' + #13#10#13#10 +
      'Trackpad scrolling and Apple keyboard settings are applied automatically. Boot Camp Control Panel remains available for your preferences; its tray starts at sign-in.';
    WizardForm.ProgressGauge.Position := WizardForm.ProgressGauge.Max;
  end else begin
    ResultText := 'Some driver stages did not complete. Click View results log for the per-driver results before retrying.';
  end;
  if RepairMode then begin
    if EngineCode = 0 then ResultText := 'The verified graphics boot route is already correct. No repair was needed.'
    else if RestartRequired and (FailedStages = 0) then ResultText := 'The recognised graphics boot entry was repaired. Restart Windows to use it. Drivers and unrelated boot files were preserved.'
    else ResultText := 'Graphics boot repair did not complete. See View results log. An unfamiliar configuration is not replaced.';
  end;
  if LayoutResult <> '' then ResultText := ResultText + #13#10#13#10 + LayoutResult;
  if SessionRoot <> '' then Log('Results and rollback records: ' + SessionRoot);
  Log(ResultText);
#endif
end;

function NeedRestart: Boolean;
begin
  Result := RestartRequired;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpReady then WizardForm.ReadyMemo.Lines.Text := PlanText;
  if (CurPageID = wpFinished) and EngineRan then begin
    WizardForm.FinishedLabel.Caption := ResultText;
    if RestartRequired then begin
      WizardForm.YesRadio.OnClick := @UpdateRestartButton;
      WizardForm.NoRadio.OnClick := @UpdateRestartButton;
      UpdateRestartButton(WizardForm);
    end;
    if (FailedStages > 0) or ((EngineCode <> 0) and not RestartRequired) then
      WizardForm.FinishedHeadingLabel.Caption := 'Driver setup needs attention';
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := 0;
  if EngineRan and (EngineCode <> 0) and (EngineCode <> 3010) then Result := EngineCode;
  if FailedStages > 0 then Result := 2;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var Code: Integer;
begin
  Result := True;
#ifndef Preview
  if (CurPageID = wpFinished) and RestartRequired and WizardForm.YesRadio.Checked then begin
    if not Exec(ExpandConstant('{sys}\shutdown.exe'), '/r /t 0', '', SW_HIDE, ewWaitUntilTerminated, Code) then Code := -1;
    if Code <> 0 then begin
      MsgBox('Windows did not accept the restart request. Save your work and restart from the Start menu. Setup logs are preserved.', mbError, MB_OK);
      Result := False;
    end else RestartRequired := False;
  end;
#endif
end;
