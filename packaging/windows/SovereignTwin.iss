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
