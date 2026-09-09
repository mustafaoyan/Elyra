; Inno Setup installer definition for a signed ELLIOT Windows build.
; The build script substitutes @VERSION@ after PyInstaller produces dist\ELLIOT.

#define MyAppName "ELLIOT"
#define MyAppVersion "@VERSION@"
#define MyAppPublisher "ELLIOT / Siper Team"
#define MyAppExeName "ELLIOT.exe"

[Setup]
AppId={{ED3E476B-76A2-4B27-A51D-C267B741C00B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
; The Windows monitor defaults to the current user's data folders, so the
; installer remains a per-user install and does not request elevation.
DefaultDirName={localappdata}\Programs\ELLIOT
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\..\dist\windows
OutputBaseFilename=ELLIOT-Setup-{#MyAppVersion}-x64
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
Source: "..\..\dist\ELLIOT\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
