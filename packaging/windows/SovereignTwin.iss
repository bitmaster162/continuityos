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
UninstallLogMode=new
UninstallFilesDir={app}\uninstall\{#RuntimeBuildId}
UninstallDisplayName=Sovereign Twin
UninstallDisplayIcon={app}\SovereignTwin-Start.exe
SetupLogging=yes
CloseApplications=no
RestartApplications=no

[Files]
Source: "{#RuntimeRoot}\*"; DestDir: "{app}\runtimes\{#RuntimeBuildId}"; Excludes: "runtime-source.json"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StableStarter}"; DestDir: "{app}"; DestName: "SovereignTwin-Start.exe"; Flags: ignoreversion onlyifdoesntexist

[Icons]
Name: "{group}\Sovereign Twin"; Filename: "{app}\SovereignTwin-Start.exe"; Parameters: "--open"; WorkingDir: "{app}"; Check: ShouldCreateStartMenuShortcut

[Code]
function CurrentUserIdentity: String;
var
  DomainName: String;
  UserName: String;
begin
  DomainName := GetEnv('USERDOMAIN');
  UserName := GetUserNameString;
  if UserName = '' then
    RaiseException('Unable to resolve current Windows user for SovereignTwin-UI task');

  if DomainName <> '' then
    Result := DomainName + '\' + UserName
  else
    Result := UserName;
end;

function CurrentTaskName: String;
var
  IdentityHash: String;
begin
  IdentityHash := GetSHA256OfUnicodeString(UpperCase(CurrentUserIdentity));
  Result := 'SovereignTwin-UI-' + Copy(IdentityHash, 1, 16);
end;

function TaskOwnershipMarker: String;
begin
  Result := ExpandConstant('{app}\installer-state\{#RuntimeBuildId}.task-owned');
end;

function XmlEscape(Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '&', '&amp;', True);
  StringChangeEx(Result, '<', '&lt;', True);
  StringChangeEx(Result, '>', '&gt;', True);
  StringChangeEx(Result, '"', '&quot;', True);
  StringChangeEx(Result, '''', '&apos;', True);
end;

function TaskExists(const TaskName: String): Boolean;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{sys}\schtasks.exe'),
    '/Query /TN "' + TaskName + '"', '', SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
  begin
    RaiseException('Unable to start schtasks.exe while querying SovereignTwin-UI task');
  end;
  Result := ResultCode = 0;
end;

function BuildTaskXml(const Identity, Starter, WorkingDir: String): String;
begin
  Result :=
    '<?xml version="1.0" encoding="UTF-8"?>' + #13#10 +
    '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' + #13#10 +
    '  <RegistrationInfo><Description>Sovereign Twin per-user UI autostart</Description></RegistrationInfo>' + #13#10 +
    '  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>' + XmlEscape(Identity) +
      '</UserId></LogonTrigger></Triggers>' + #13#10 +
    '  <Principals><Principal id="Author"><UserId>' + XmlEscape(Identity) +
      '</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>' + #13#10 +
    '  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>' +
      '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>' +
      '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>' +
      '<StartWhenAvailable>true</StartWhenAvailable><AllowStartOnDemand>true</AllowStartOnDemand>' +
      '<Enabled>true</Enabled><Hidden>false</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>' + #13#10 +
    '  <Actions Context="Author"><Exec><Command>' + XmlEscape(Starter) + '</Command>' +
      '<Arguments>--serve</Arguments><WorkingDirectory>' + XmlEscape(WorkingDir) +
      '</WorkingDirectory></Exec></Actions>' + #13#10 +
    '</Task>';
end;

procedure CreateAutostartTask;
var
  ResultCode: Integer;
  TaskName: String;
  TaskXml: String;
  Identity: String;
  Starter: String;
  Marker: String;
  MarkerDir: String;
  Xml: String;
begin
  TaskName := CurrentTaskName;
  if TaskExists(TaskName) then
  begin
    Log('Preserving pre-existing per-user SovereignTwin-UI task: ' + TaskName);
    Exit;
  end;

  Identity := CurrentUserIdentity;
  Starter := ExpandConstant('{app}\SovereignTwin-Start.exe');
  TaskXml := ExpandConstant('{tmp}\SovereignTwin-UI-' +
    Copy(GetSHA256OfUnicodeString(UpperCase(Identity)), 1, 16) + '.xml');
  Xml := BuildTaskXml(Identity, Starter, ExpandConstant('{app}'));

  if not SaveStringToFile(TaskXml, Utf8Encode(Xml), False) then
    RaiseException('Unable to write temporary SovereignTwin-UI task XML');

  try
    if not Exec(ExpandConstant('{sys}\schtasks.exe'),
      '/Create /TN "' + TaskName + '" /XML "' + TaskXml + '"', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode) then
    begin
      RaiseException('Unable to start schtasks.exe while creating SovereignTwin-UI task');
    end;

    if ResultCode <> 0 then
      RaiseException(Format(
        'schtasks.exe failed while creating SovereignTwin-UI task (exit code %d)',
        [ResultCode]));

    if not TaskExists(TaskName) then
      RaiseException('SovereignTwin-UI task missing immediately after creation');

    Marker := TaskOwnershipMarker;
    MarkerDir := ExtractFileDir(Marker);
    if not ForceDirectories(MarkerDir) then
      RaiseException('Unable to create installer-state directory for task ownership');

    if not SaveStringToFile(Marker, Utf8Encode(TaskName), False) then
      RaiseException('Unable to persist SovereignTwin-UI task ownership marker');
  finally
    DeleteFile(TaskXml);
  end;
end;

procedure DeleteOwnedAutostartTask;
var
  ResultCode: Integer;
  TaskName: String;
  Marker: String;
begin
  Marker := TaskOwnershipMarker;
  if not FileExists(Marker) then
  begin
    Log('No task ownership marker for this build; preserving pre-existing SovereignTwin-UI task');
    Exit;
  end;

  TaskName := CurrentTaskName;
  if TaskExists(TaskName) then
  begin
    if not Exec(ExpandConstant('{sys}\schtasks.exe'),
      '/Delete /F /TN "' + TaskName + '"', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode) then
    begin
      RaiseException('Unable to start schtasks.exe while deleting owned SovereignTwin-UI task');
    end;

    if ResultCode <> 0 then
      RaiseException(Format(
        'schtasks.exe failed while deleting owned SovereignTwin-UI task (exit code %d)',
        [ResultCode]));

    if TaskExists(TaskName) then
      RaiseException('Owned SovereignTwin-UI task still exists after deletion');
  end;

  DeleteFile(Marker);
end;

function ShouldCreateStartMenuShortcut: Boolean;
begin
  Result := not FileExists(ExpandConstant('{group}\Sovereign Twin.lnk'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    CreateAutostartTask;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    DeleteOwnedAutostartTask;
end;
