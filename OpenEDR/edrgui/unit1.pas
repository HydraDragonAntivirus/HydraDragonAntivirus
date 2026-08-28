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
  Windows, Registry, USvcControl, UAlert, UGuiNotify, UHipPipe;

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
    MenuPauseResume: TMenuItem;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure MenuExitClick(Sender: TObject);
    procedure MenuInstallClick(Sender: TObject);
    procedure MenuRestartClick(Sender: TObject);
    procedure MenuStartClick(Sender: TObject);
    procedure MenuStopClick(Sender: TObject);
    procedure MenuUninstallClick(Sender: TObject);
    procedure MenuPauseResumeClick(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
  private
    FAgentExePath: string;
    FLastState: TSvcState;
    FBusy: Boolean;
    FRestartPending: Boolean;
    FNotifier: TGuiNotifierThread;
    FHiPPipe: THipPipeListener;
    FProtectionPaused: Boolean;
    function ReadProtectionPaused: Boolean;
    procedure WriteProtectionPaused(APaused: Boolean);
    procedure SetPauseCaption(APaused: Boolean);
    procedure RunCommand(ACmd: TSvcCommand);
    procedure OnCommandDone(Sender: TObject; Cmd: TSvcCommand;
      Success: Boolean; ExitCode: DWORD; const Output: string);
    procedure OnNotifierDetections(Sender: TObject;
      const Detections: TDetInfoArray);
    procedure OnHipMessage(Sender: TObject; const AKind, AText: string);
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

  // Pause/Resume Protection toggle (writes HKLM\SOFTWARE\Owlyshield!
  // PROTECTION_PAUSED; the agent picks it up within ~2 seconds).
  MenuPauseResume := TMenuItem.Create(Self);
  MenuPauseResume.OnClick := @MenuPauseResumeClick;
  PopupMenu1.Items.Insert(PopupMenu1.Items.IndexOf(MenuStatus) + 1,
    MenuPauseResume);
  SetPauseCaption(ReadProtectionPaused);

  FNotifier := TGuiNotifierThread.Create(@OnNotifierDetections);
  FHiPPipe := THipPipeListener.Create(@OnHipMessage);
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  if FNotifier <> nil then
  begin
    FNotifier.Terminate;
    FNotifier := nil;
  end;
  if FHiPPipe <> nil then
  begin
    FHiPPipe.Terminate;
    FHiPPipe := nil;
  end;
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
  GUI_ICON_FILE = 'edrgui.ico';

function ExtractIconW(hInst: HINST; lpszExeFileName: PWideChar;
  nIconIndex: UINT): QWord; stdcall; external SHELL32_DLL name 'ExtractIconW';

// Loads the base tray/application icon. Prefers the standalone edrgui.ico
// shipped next to the exe; falls back to the icon embedded in edrsvc.exe.
// Called once at startup; LoadStateIcon() may later override it with a
// custom icons\*.ico file.
procedure TForm1.LoadAgentIcon;
var
  IconFile: string;
  hIcon: QWord;
  TmpIcon: TIcon;
begin
  IconFile := ExtractFilePath(ParamStr(0)) + GUI_ICON_FILE;

  if FileExists(IconFile) then
  begin
    TmpIcon := TIcon.Create;
    try
      TmpIcon.LoadFromFile(IconFile);
      TrayIcon1.Icon.Assign(TmpIcon);
      if (Application.Icon <> nil) and not Application.Icon.Empty then
        Application.Icon.Assign(TmpIcon);
    finally
      TmpIcon.Free;
    end;
    Exit;
  end;

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

  // Reflect the protection-pause toggle on top of the service state.
  if ReadProtectionPaused then
  begin
    LoadStateIcon('off');
    TrayIcon1.Hint := TrayIcon1.Hint + LineEnding + 'Protection: PAUSED';
  end;
  SetPauseCaption(ReadProtectionPaused);

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

// Runs on the main thread (via Synchronize) whenever the notifier thread
// pulls new detection events from the edrsvc RPC server.
procedure TForm1.OnNotifierDetections(Sender: TObject;
  const Detections: TDetInfoArray);
var
  sMsg, sTitle: string;
  i: Integer;
  Sev: TAlertSeverity;
begin
  if Length(Detections) = 0 then
    Exit;

  sTitle := Trim(Detections[0].Title);
  if sTitle = '' then
    sTitle := Detections[0].EventType;

  sMsg := '';
  Sev := asInfo;
  for i := 0 to High(Detections) do
  begin
    if Pos('MLE_', Detections[i].EventType) = 1 then
      Sev := asCritical
    else if (Detections[i].FlsVerdict = 2) or (Detections[i].Verdict = 2) then
      Sev := asCritical;
      
    if sMsg <> '' then
      sMsg := sMsg + LineEnding;
    if Detections[i].Title <> '' then
      sMsg := sMsg + Detections[i].Title + ': '
    else if Detections[i].EventType <> '' then
      sMsg := sMsg + Detections[i].EventType + ': ';
    if Detections[i].ImagePath <> '' then
      sMsg := sMsg + Detections[i].ImagePath;
      
    if Detections[i].AttackChain <> '' then
      sMsg := sMsg + LineEnding + '  Attack Chain: ' + Detections[i].AttackChain;
  end;

  sTitle := Trim(sTitle);
  sMsg := Trim(sMsg);
  if (sTitle = '') and (sMsg = '') then
    Exit;

  TAlertForm.ShowAlert(sTitle, sMsg, Sev, 0);
end;

// Runs on the main thread (via Synchronize) whenever the Rust behavior engine
// writes a message to the HydraHipEvent pipe (threat alert, HIPS prompt,
// verdict, ...).
procedure TForm1.OnHipMessage(Sender: TObject; const AKind, AText: string);
var
  CleanKind, CleanText: string;
begin
  CleanKind := Trim(AKind);
  CleanText := Trim(AText);
  if (CleanKind = '') and (CleanText = '') then
    Exit;

  TAlertForm.ShowAlert(CleanKind, CleanText, asInfo, 0);
end;

// ---------------------------------------------------------------------------
// Pause / Resume Protection
//
// The toggle lives in HKLM\SOFTWARE\Owlyshield!PROTECTION_PAUSED ("1"/"0").
// The agent re-reads it at most once per second; while set, only detection
// *actions* (quarantine/kill) are suppressed — monitoring and event flow
// keep running.
// ---------------------------------------------------------------------------

function TForm1.ReadProtectionPaused: Boolean;
begin
  Result := FProtectionPaused;
end;

procedure TForm1.WriteProtectionPaused(APaused: Boolean);
var
  Req, Resp: string;
begin
  if APaused then
    Req := '{"jsonrpc":"2.0","id":1,"method":"setProtectionPaused","params":{"paused":true}}'
  else
    Req := '{"jsonrpc":"2.0","id":1,"method":"setProtectionPaused","params":{"paused":false}}';

  // Send directly to edrsvc in-memory via JSON-RPC
  HttpPostJson(GUI_RPC_HOST, GUI_RPC_PORT, Req, Resp);

  FProtectionPaused := APaused;
  SetPauseCaption(APaused);

  if APaused then
  begin
    LoadStateIcon('off');
    TrayIcon1.Hint := 'HydraDragon EDR Agent' + LineEnding +
      'Status: Protection PAUSED';
    TAlertForm.ShowAlert('Protection paused',
      'Detection and quarantine actions are suspended in edrsvc.',
      asWarning, 4000);
  end
  else
  begin
    LoadStateIcon('on');
    TrayIcon1.Hint := 'HydraDragon EDR Agent' + LineEnding +
      'Status: Protected';
    TAlertForm.ShowAlert('Protection resumed',
      'Detection and quarantine actions are active again.',
      asSuccess, 3000);
  end;
end;

procedure TForm1.SetPauseCaption(APaused: Boolean);
begin
  if MenuPauseResume <> nil then
  begin
    if APaused then
      MenuPauseResume.Caption := 'Resume Protection'
    else
      MenuPauseResume.Caption := 'Pause Protection';
  end;
end;

procedure TForm1.MenuPauseResumeClick(Sender: TObject);
begin
  WriteProtectionPaused(not ReadProtectionPaused);
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
  else
    sTitle := 'Service operation';
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