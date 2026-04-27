; Inno Setup script for PWNAudit NetScope
; Compiles to dist\PWNAudit-NetScope-Setup.exe — the file to ship from pwnaudit.com.

#define MyAppName        "PWNAudit NetScope"
#define MyAppShortName   "PWNAudit-NetScope"
#define MyAppVersion     "0.1.0"
#define MyAppPublisher   "PWNAudit"
#define MyAppURL         "https://pwnaudit.com"
#define MyAppExeName     "PWNAudit-NetScope.exe"

[Setup]
; AppId uniquely identifies this application for upgrades / uninstall.
; Do NOT change after the first public release.
AppId={{B8E1F4A2-7C8D-4E5F-9D2A-CCAA12BB34DD}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
UsePreviousAppDir=yes

OutputDir=..\dist
OutputBaseFilename={#MyAppShortName}-Setup
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

SetupIconFile=..\assets\pwnaudit.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
ShowLanguageDialog=no
WizardImageStretch=no
CloseApplications=yes

VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoProductName={#MyAppName}
VersionInfoVersion={#MyAppVersion}.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md";              DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Top-level Start Menu entry — appears immediately in Windows Search when typing "pwnaudit"
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Comment: "Live network protocol analyzer"
; Optional desktop shortcut
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Auto-launch on finish (default checkbox in wizard)
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[Code]
function NpcapInstalled(): Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'))
         or FileExists(ExpandConstant('{sys}\Npcap\packet.dll'))
         or FileExists(ExpandConstant('{sys}\wpcap.dll'))
         or FileExists(ExpandConstant('{syswow64}\wpcap.dll'))
         or FileExists(ExpandConstant('{sys}\drivers\npcap.sys'))
         or FileExists(ExpandConstant('{sys}\drivers\npcap_wifi.sys'));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if not NpcapInstalled() then
    begin
      if MsgBox(
        'PWNAudit NetScope needs Npcap to capture network packets.' #13#10 #13#10 +
        'Npcap is the same packet-capture library Wireshark uses on Windows. ' +
        'It is a separate one-time install (kernel driver).' #13#10 #13#10 +
        'Open the download page now?',
        mbConfirmation, MB_YESNO) = IDYES then
      begin
        ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOW, ewNoWait, ResultCode);
      end;
    end;
  end;
end;
