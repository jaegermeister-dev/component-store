; Standard Windows wizard. The engine and payload remain model-filtered and
; hash pinned. No Windows driver is redistributed inside this small EXE.
#ifndef Engine
  #error Engine is required
#endif
#ifndef BuildOutput
  #error BuildOutput is required
#endif
[Setup]
AppId=NoMoreBCA-Community-Windows7-Drivers
AppName=NoMoreBCA Windows 7 Drivers
AppVersion=0.2.0
AppPublisher=NoMoreBCA
DefaultDirName={autopf}\NoMoreBCA
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
SetupLogging=yes
AllowCancelDuringInstall=no
CloseApplications=no
RestartApplications=no
OutputDir={#BuildOutput}
#ifdef Preview
OutputBaseFilename=Driver-Wizard-Preview
#else
OutputBaseFilename=NoMoreBCA-Driver-Setup
#endif
Compression=lzma2
SolidCompression=yes
VersionInfoDescription=NoMoreBCA Windows 7 Driver Setup
[Files]
Source: "{#Engine}"; DestName: "NoMoreBCA-Driver-Engine.exe"; Flags: dontcopy
[Messages]
WelcomeLabel1=Welcome to NoMoreBCA Driver Setup
WelcomeLabel2=This wizard installs the applicable Windows 7 drivers and Boot Camp Control Panel for your Mac.%n%nAll drivers are prepared by NoMoreBCA. No Internet connection is needed in Windows.%n%nSetup may need to restart Windows before finishing. Normal administrator approval and Windows driver-signature checks remain enabled.
ReadyLabel1=Setup is ready to install the applicable drivers.
ReadyLabel2a=Click Install to begin. There is no need to select or install individual driver packages.
FinishedHeadingLabel=Driver setup results
[Code]
var
  Details: TNewMemo;
  ViewLog: TNewButton;
  SessionRoot, PayloadRoot: String;
  EngineCode, ResumeCount: Integer;
  RestartRequired, ResumeRegistered, EngineRan: Boolean;
  ResultText, PlanText: String;

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
  if Pos('NMBCA_SESSION|', S) = 1 then begin
    SessionRoot := Copy(S, 15, MaxInt);
    Exit;
  end;
  if Pos('NMBCA_PROGRESS|', S) = 1 then begin
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
    'Includes Wi-Fi, keyboard, Bluetooth, Intel Management Engine, audio, graphics (11,5 only), trackpad and Boot Camp Control Panel.' + #13#10#13#10 +
    'MacBookPro11,4 remains experimental and receives no AMD drivers. Internal Fn/backlight and dock Ethernet are not fixed by this package.' + #13#10#13#10 +
    'If a restart is required, setup will offer to restart and resume after sign-in. You may need to approve UAC again.';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
#ifndef Preview
  if not FileExists(AddBackslash(PayloadRoot) + 'Payload\Microsoft-SHA2-Update\Windows6.1-KB3033929-x64.msu') then
    Result := 'The downloaded driver files are missing. Keep this installer beside its Payload folder, as prepared by NoMoreBCA.';
#endif
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ContinueExe, ResumeExe, Engine: String;
  Code: Integer;
begin
  if CurStep <> ssPostInstall then Exit;
#ifdef Preview
  { Compile-time developer preview: contains NO engine execution, restart or
    continuation registration. This binary is never delivered to users. }
  EngineRan := True;
  EngineCode := 0;
  EngineLog('NMBCA_PROGRESS|10|10|Driver setup complete', False, True);
  ResultText := 'PREVIEW ONLY - no drivers installed.' + #13#10#13#10 +
    'All applicable driver stages completed. Open Boot Camp Control Panel to enable your preferred trackpad options. Its tray icon starts at your next Windows sign-in.';
#else
  ExtractTemporaryFile('NoMoreBCA-Driver-Engine.exe');
  Engine := ExpandConstant('{tmp}\NoMoreBCA-Driver-Engine.exe');
  EngineCode := 1;
  EngineRan := True;
  WizardForm.StatusLabel.Caption := 'Checking hardware and driver files...';
  try
    if not ExecAndLogOutput(Engine, '--install "' + PayloadRoot + '"', PayloadRoot,
      SW_HIDE, ewWaitUntilTerminated, EngineCode, @EngineLog) then
      Details.Lines.Add('The driver engine could not start: ' + SysErrorMessage(EngineCode));
  except
    Details.Lines.Add(GetExceptionMessage);
    EngineCode := 1;
  end;
  RestartRequired := EngineCode = 3010;
  ResumeRegistered := False;
  if RestartRequired and (ResumeCount < 3) and
    (Pos(AddBackslash(ExpandConstant('{commonappdata}')) + 'NoMoreBCA-Driver-Setup-{', SessionRoot) = 1) and
    FileExists(AddBackslash(SessionRoot) + 'expected-files.csv') then begin
    ContinueExe := AddBackslash(SessionRoot) + 'Continue-Driver-Setup.exe';
    ResumeExe := AddBackslash(SessionRoot) + 'NoMoreBCA-Resume.exe';
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
    ResultText := 'Windows needs a restart to finish installing drivers.';
    if ResumeRegistered then ResultText := ResultText + #13#10#13#10 +
      'Setup will reopen after sign-in. Approve Windows UAC and click Install to continue.'
    else ResultText := ResultText + #13#10#13#10 +
      'After restarting, run NoMoreBCA-Driver-Setup.exe again. Automatic continuation is unavailable.';
  end else if EngineCode = 0 then begin
    ResultText := 'All applicable driver stages completed. Physical functions still need testing.' + #13#10#13#10 +
      'Enable trackpad options in Boot Camp Control Panel. Its tray starts at your next sign-in.';
    WizardForm.ProgressGauge.Position := WizardForm.ProgressGauge.Max;
  end else begin
    ResultText := 'Some driver stages did not complete. Click View results log for the per-driver results before retrying.';
  end;
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
    if (EngineCode <> 0) and not RestartRequired then
      WizardForm.FinishedHeadingLabel.Caption := 'Driver setup needs attention';
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  Result := 0;
  if EngineRan and (EngineCode <> 0) and (EngineCode <> 3010) then Result := EngineCode;
end;
