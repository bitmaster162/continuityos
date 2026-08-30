#ifndef RuntimeRoot
  #error RuntimeRoot define is required
#endif
#ifndef RuntimeBuildId
  #error RuntimeBuildId define is required
#endif
#ifndef StableStarter
  #error StableStarter define is required
#endif
#ifndef ProductVersion
  #error ProductVersion define is required
#endif
#ifndef SourceSha
  #error SourceSha define is required
#endif
#ifndef OutputDir
  #error OutputDir define is required
#endif

[Setup]
AppId=SovereignTwin.Windows
AppName=Sovereign Twin
AppVersion={#ProductVersion}
AppPublisher=ContinuityOS
AppComments=Source SHA: {#SourceSha}
DefaultDirName={localappdata}\SovereignTwin
DefaultGroupName=Sovereign Twin
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=SovereignTwin-Setup-{#ProductVersion}-win-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
Uninstallable=yes
CreateUninstallRegKey=yes
UninstallDisplayName=Sovereign Twin
UninstallDisplayIcon={app}\SovereignTwin-Start.exe
SetupLogging=yes
CloseApplications=no
RestartApplications=no

[Files]
Source: "{#RuntimeRoot}\*"; DestDir: "{app}\runtimes\{#RuntimeBuildId}"; Excludes: "runtime-source.json"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StableStarter}"; DestDir: "{app}"; DestName: "SovereignTwin-Start.exe"; Flags: ignoreversion

[Icons]
Name: "{group}\Sovereign Twin"; Filename: "{app}\SovereignTwin-Start.exe"; Parameters: "--open"; WorkingDir: "{app}"

[Code]
const
  ScheduledTaskName = 'SovereignTwin-UI';

procedure CreateAutostartTask;
var
  ResultCode: Integer;
  Starter: String;
  Params: String;
begin
  Starter := ExpandConstant('{app}\SovereignTwin-Start.exe');
  Params := '/Create /F /SC ONLOGON /RL LIMITED /TN "' + ScheduledTaskName +
    '" /TR "\"' + Starter + '\" --serve"';

  if not Exec(ExpandConstant('{sys}\schtasks.exe'), Params, '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
  begin
    RaiseException('Unable to start schtasks.exe while creating SovereignTwin-UI');
  end;

  if ResultCode <> 0 then
  begin
    RaiseException(Format('schtasks.exe failed while creating SovereignTwin-UI (exit code %d)', [ResultCode]));
  end;
end;

procedure DeleteAutostartTask;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\schtasks.exe'),
    '/Delete /F /TN "' + ScheduledTaskName + '"', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    CreateAutostartTask;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    DeleteAutostartTask;
  end;
end;
