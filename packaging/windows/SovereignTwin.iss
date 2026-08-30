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
#ifndef P1CEnableExistingBindingActivation
  #define P1CEnableExistingBindingActivation 0
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
UninstallLogMode=append
UninstallFilesDir={app}\uninstall
UninstallDisplayName=Sovereign Twin
UninstallDisplayIcon={app}\SovereignTwin-Start.exe
SetupLogging=yes
CloseApplications=no
RestartApplications=no

[Files]
Source: "{#RuntimeRoot}\*"; DestDir: "{app}\runtimes\{#RuntimeBuildId}"; Excludes: "runtime-source.json"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StableStarter}"; DestDir: "{app}"; DestName: "SovereignTwin-Start.exe"; Flags: ignoreversion onlyifdoesntexist

[Icons]
Name: "{userstartup}\Sovereign Twin UI"; Filename: "{app}\SovereignTwin-Start.exe"; Parameters: "--serve"; WorkingDir: "{app}"; Check: ShouldCreateAutostartShortcut
Name: "{group}\Sovereign Twin"; Filename: "{app}\SovereignTwin-Start.exe"; Parameters: "--open"; WorkingDir: "{app}"; Check: ShouldCreateStartMenuShortcut

[Code]
function ShouldCreateAutostartShortcut: Boolean;
begin
  Result := not FileExists(ExpandConstant('{userstartup}\Sovereign Twin UI.lnk'));
  if not Result then
    Log('Preserving pre-existing per-user Startup shortcut: ' +
      ExpandConstant('{userstartup}\Sovereign Twin UI.lnk'));
end;

function ShouldCreateStartMenuShortcut: Boolean;
begin
  Result := not FileExists(ExpandConstant('{group}\Sovereign Twin.lnk'));
  if not Result then
    Log('Preserving pre-existing Start Menu shortcut: ' +
      ExpandConstant('{group}\Sovereign Twin.lnk'));
end;

#if P1CEnableExistingBindingActivation == 1
procedure CurStepChanged(CurStep: TSetupStep);
var
  PythonExe: String;
  RuntimeRootPath: String;
  PointerPath: String;
  StarterPath: String;
  Params: String;
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then
    Exit;

  PointerPath := ExpandConstant('{app}\runtime-source.json');
  if not FileExists(PointerPath) then
  begin
    Log('P1C activation skipped: no existing runtime-source.json binding');
    Exit;
  end;

  RuntimeRootPath := ExpandConstant('{app}\runtimes\{#RuntimeBuildId}');
  PythonExe := RuntimeRootPath + '\python.exe';
  StarterPath := ExpandConstant('{app}\SovereignTwin-Start.exe');
  Params := '-B -I -m continuityos.windows_product_transaction --p1c-write activate' +
    ' --runtime-root "' + RuntimeRootPath + '"' +
    ' --pointer "' + PointerPath + '"' +
    ' --starter "' + StarterPath + '"';

  Log('P1C delegating existing-binding activation to staged packaged Python');
  if not Exec(PythonExe, Params, ExpandConstant('{app}'), SW_HIDE,
    ewWaitUntilTerminated, ResultCode) then
    RaiseException('P1C activation helper could not be started');
  if ResultCode <> 0 then
    RaiseException('P1C activation helper failed rc=' + IntToStr(ResultCode));
end;
#endif
