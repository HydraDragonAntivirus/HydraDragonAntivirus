unit Unit1;

{ ---------------------------------------------------------------------------
  Unit1 / TForm1  -  HydraDragon EDR Agent Controller (system tray)
  ---------------------------------------------------------------------------
  This form is never visible (Visible=False, ShowInTaskBar=stNever).
  Its only job is to show an icon in the system tray with a right-click
  menu and to run edrsvc.exe with "start" / "stop" / "install" /
  "uninstall" arguments. Status changes and errors are shown as "toasts"
  via UAlert; no persistent window is opened.
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, ExtCtrls, Menus,
  Windows, USvcControl, UAlert;

type

  { TForm1 }

  TForm1 = class(TForm)
    MenuAllowUnload: TMenuItem;
    MenuExit: TMenuItem;
    MenuInstall: TMenuItem;
    MenuUninstall: TMenuItem;
    MenuRestart: TMenuItem;
    MenuStart: TMenuItem;
    MenuStatus: TMenuItem;
    MenuStop: TMenuItem;
    N1: TMenuItem;
    N2: TMenuItem;
    N3: TMenuItem;
    PopupMenu1: TPopupMenu;
    Timer1: TTimer;
    TrayIcon1: TTrayIcon;
    procedure FormCreate(Sender: TObject);
    procedure MenuExitClick(Sender: TObject);
    procedure MenuInstallClick(Sender: TObject);
    procedure MenuRestartClick(Sender: TObject);
    procedure MenuStartClick(Sender: TObject);
    procedure MenuStopClick(Sender: TObject);
    procedure MenuUninstallClick(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
  private
    FAgentExePath: string;
    FLastState: TSvcState;
    FBusy: Boolean;
    FRestartPending: Boolean;
    procedure RunCommand(ACmd: TSvcCommand);
    procedure OnCommandDone(Sender: TObject; Cmd: TSvcCommand;
      Success: Boolean; ExitCode: DWORD; const Output: string);
    procedure RefreshStatus(AShowChangeAlert: Boolean);
    procedure UpdateMenuEnabled(AState: TSvcState);
    procedure LoadStateIcon(const AFileNameNoExt: string);
    procedure LoadAgentIcon;
  public

  end;

var
  Form1: TForm1;

implementation

{$R *.lfm}

{ TForm1 }

procedure TForm1.FormCreate(Sender: TObject);
begin
  // This window must never be visible; the app is managed entirely from
  // the tray icon
  Visible := False;
  ShowInTaskBar := stNever;
  BorderStyle := bsNone;

  FAgentExePath := ResolveAgentExePath;
  FBusy := False;
  FRestartPending := False;
  FLastState := ssUnknown;

  TrayIcon1.Hint := 'HydraDragon EDR Agent';
  LoadAgentIcon;          // base icon from edrsvc.exe
  LoadStateIcon('off');   // overrides it if icons\off.ico exists
  if TrayIcon1.Icon.Empty and (Application.Icon <> nil) and
     not Application.Icon.Empty then
    TrayIcon1.Icon.Assign(Application.Icon);
  TrayIcon1.Show;

  RefreshStatus(False);
  Timer1.Interval := 4000;
  Timer1.Enabled := True;
end;

// Loads one of icons\ok.ico / warn.ico / error.ico / busy.ico / off.ico
// into the tray icon (if missing, the current icon stays).
// You can place your own HydraDragon logo in the icons\ folder with these
// names.
procedure TForm1.LoadStateIcon(const AFileNameNoExt: string);
var
  sPath: string;
begin
  sPath := ExtractFilePath(ParamStr(0)) + 'icons' + PathDelim +
    AFileNameNoExt + '.ico';
  if FileExists(sPath) then
  begin
    try
      TrayIcon1.Icon.LoadFromFile(sPath);
    except
      // silently ignore: a corrupt/unsupported icon file must not stop the app
    end;
  end;
end;

const
  SHELL32_DLL = 'shell32.dll';

function ExtractIconW(hInst: HINST; lpszExeFileName: PWideChar;
  nIconIndex: UINT): QWord; stdcall; external SHELL32_DLL name 'ExtractIconW';

// Loads the icon embedded in edrsvc.exe as the base tray/application icon.
// Called once at startup; LoadStateIcon() may later override it with a
// custom icons\*.ico file.
procedure TForm1.LoadAgentIcon;
var
  hIcon: QWord;
  TmpIcon: TIcon;
begin
  if not FileExists(FAgentExePath) then
    Exit;

  hIcon := ExtractIconW(0, PWideChar(UnicodeString(FAgentExePath)), 0);
  if hIcon = 0 then
    Exit;

  TmpIcon := TIcon.Create;
  try
    // TIcon takes ownership of the extracted handle and frees it via
    // DestroyIcon when TmpIcon is freed.
    TmpIcon.Handle := hIcon;
    TrayIcon1.Icon.Assign(TmpIcon);
    if (Application.Icon <> nil) and not Application.Icon.Empty then
      Application.Icon.Assign(TmpIcon);
  finally
    TmpIcon.Free;
  end;
end;

procedure TForm1.UpdateMenuEnabled(AState: TSvcState);
var
  fInstalled: Boolean;
begin
  fInstalled := AState <> ssNotInstalled;

  MenuStart.Enabled := (not FBusy) and fInstalled and
    (AState in [ssStopped, ssPaused]);
  MenuStop.Enabled := (not FBusy) and fInstalled and
    (AState in [ssRunning, ssStartPending, ssContinuePending]);
  MenuRestart.Enabled := (not FBusy) and fInstalled and
    (AState = ssRunning);
  MenuInstall.Enabled := (not FBusy) and (not fInstalled);
  MenuUninstall.Enabled := (not FBusy) and fInstalled;
end;

procedure TForm1.RefreshStatus(AShowChangeAlert: Boolean);
var
  NewState: TSvcState;
  WasRunning: Boolean;
begin
  NewState := GetServiceState(EDR_SERVICE_NAME);

  if AShowChangeAlert and (NewState <> FLastState) then
  begin
    WasRunning := FLastState in [ssRunning, ssStartPending, ssContinuePending];
    if WasRunning and (NewState = ssStopped) and (not FBusy) then
      TAlertForm.ShowAlert('EDR service stopped',
        'The HydraDragon EDR agent stopped unexpectedly. Your system may ' +
        'currently be unprotected.', asCritical, 0)
    else if (FLastState = ssNotInstalled) and (NewState = ssStopped) then
      TAlertForm.ShowAlert('Service installed',
        'The HydraDragon EDR agent was installed successfully.', asSuccess, 5000);
  end;

  FLastState := NewState;
  TrayIcon1.Hint := 'HydraDragon EDR Agent' + LineEnding +
    'Status: ' + SvcStateToStr(NewState);
  MenuStatus.Caption := 'Status: ' + SvcStateToStr(NewState);

  case NewState of
    ssRunning:                              LoadStateIcon('ok');
    ssStopped, ssPaused:                    LoadStateIcon('off');
    ssNotInstalled:                         LoadStateIcon('off');
    ssStartPending, ssStopPending,
    ssContinuePending, ssPausePending:      LoadStateIcon('busy');
  else
    LoadStateIcon('warn');
  end;

  UpdateMenuEnabled(NewState);
end;

procedure TForm1.Timer1Timer(Sender: TObject);
begin
  RefreshStatus(True);
end;

procedure TForm1.TrayIcon1DblClick(Sender: TObject);
begin
  TAlertForm.ShowAlert('HydraDragon EDR Agent',
    'Current status: ' + SvcStateToStr(FLastState), asInfo, 4000);
end;

procedure TForm1.RunCommand(ACmd: TSvcCommand);
begin
  if FBusy then
  begin
    TAlertForm.ShowAlert('Busy', 'Another operation is still running, please wait.',
      asWarning, 3000);
    Exit;
  end;

  FBusy := True;
  UpdateMenuEnabled(FLastState);
  LoadStateIcon('busy');
  TrayIcon1.Hint := 'HydraDragon EDR Agent' + LineEnding + 'Operation in progress...';

  TSvcCommandThread.Create(FAgentExePath, CommandToArg(ACmd), ACmd,
    @OnCommandDone);
end;

procedure TForm1.OnCommandDone(Sender: TObject; Cmd: TSvcCommand;
  Success: Boolean; ExitCode: DWORD; const Output: string);
var
  sTitle, sMsg: string;
begin
  FBusy := False;

  case Cmd of
    scStart:     sTitle := 'Start service';
    scStop:      sTitle := 'Stop service';
    scInstall:   sTitle := 'Install service';
    scUninstall: sTitle := 'Uninstall service';
  end;

  if Success then
  begin
    sMsg := sTitle + ' completed successfully.';
    TAlertForm.ShowAlert(sTitle, sMsg, asSuccess, 4000);
  end
  else
  begin
    sMsg := sTitle + ' failed (exit code: ' + IntToStr(ExitCode) + ').';
    if Output <> '' then
      sMsg := sMsg + LineEnding + Output;
    TAlertForm.ShowAlert(sTitle + ' failed', sMsg, asCritical, 0);
  end;

  // Restart = stop first, then start if it succeeded
  if FRestartPending and (Cmd = scStop) then
  begin
    FRestartPending := False;
    if Success then
      RunCommand(scStart);
  end;

  RefreshStatus(False);
end;

procedure TForm1.MenuStartClick(Sender: TObject);
begin
  RunCommand(scStart);
end;

procedure TForm1.MenuStopClick(Sender: TObject);
begin
  RunCommand(scStop);
end;

procedure TForm1.MenuRestartClick(Sender: TObject);
begin
  FRestartPending := True;
  RunCommand(scStop);
end;

procedure TForm1.MenuInstallClick(Sender: TObject);
begin
  if MessageDlg('Install service',
       'The HydraDragon EDR agent will be installed as a Windows service. ' +
       'Continue?', mtConfirmation, [mbYes, mbNo], 0) = mrYes then
    RunCommand(scInstall);
end;

procedure TForm1.MenuUninstallClick(Sender: TObject);
begin
  if MessageDlg('Uninstall service',
       'The HydraDragon EDR agent will be removed from the system and ' +
       'protection will stop. Continue?', mtWarning, [mbYes, mbNo], 0) = mrYes then
    RunCommand(scUninstall);
end;

procedure TForm1.MenuExitClick(Sender: TObject);
begin
  TrayIcon1.Visible := False;
  Application.Terminate;
end;

end.