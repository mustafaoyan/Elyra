#define MyAppName "ELYRA AI Assistant"
#define MyAppVersion "@VERSION@"
#define MyAppPublisher "ELYRA / Elyra Team"
#define MyAppExeName "ELYRA-AI.exe"
[Setup]
AppId={{F4BBE57C-B8C4-43CF-92DF-EA79B15903AC}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\ELYRA AI Assistant
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\..\dist\windows-ai
OutputBaseFilename=ELYRA-AI-Setup-{#MyAppVersion}-x64
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
WizardStyle=modern
[Files]
Source: "..\..\dist\ELYRA-AI\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"
[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent
