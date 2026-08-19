unit USvcControl;

{ ---------------------------------------------------------------------------
  USvcControl
  ---------------------------------------------------------------------------
  Helper unit that talks to edrsvc.exe (see service.cpp / WinService class).
  It does two things:

    1) GetServiceState()  -> reads the service's REAL state via the SCM
                              (Windows API, without touching edrsvc.exe).

    2) TSvcCommandThread   -> runs "edrsvc.exe start" / "edrsvc.exe stop"
                              etc. IN THE BACKGROUND (without blocking the
                              GUI) and reports the result to the main thread.

  NOTE: Starting/stopping the service requires administrator rights. The
  GUI itself runs asInvoker (edrgui.lpi manifest) so that the edrsvc service
  can launch it into the interactive session via CreateProcessAsUser (a
  requireAdministrator manifest would fail with ERROR_ELEVATION_REQUIRED).
  Each privileged command (start/stop/install/uninstall) is executed by
  spawning "edrsvc.exe <cmd>", which elevates itself via UAC (see
  startElevatedInstance in mode_*.cpp).
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Windows;

const
  // Registered service name for HydraDragonAntivirus. MUST match the
  // c_sServiceName constant in service.cpp. Change it here if needed.
  EDR_SERVICE_NAME = 'edrsvc';

  // ---------------------------------------------------------------------
  // The "WinSvc" unit comes as a separate, optional package in some
  // FPC/Lazarus installations and may not be in the default compiler
  // search path ("WinSvc not found" error). That is why the few required
  // Service Control Manager functions/constants are linked directly to
  // advapi32.dll, WITHOUT requiring any external package.
  // ---------------------------------------------------------------------
  ADVAPI32_DLL = 'advapi32.dll';

  SC_MANAGER_CONNECT = $0001;
  SERVICE_QUERY_STATUS = $0004;

  SERVICE_STOPPED          = $00000001;
  SERVICE_START_PENDING    = $00000002;
  SERVICE_STOP_PENDING     = $00000003;
  SERVICE_RUNNING          = $00000004;
  SERVICE_CONTINUE_PENDING = $00000005;
  SERVICE_PAUSE_PENDING    = $00000006;
  SERVICE_PAUSED           = $00000007;

type
  SC_HANDLE = THandle;

  TServiceStatus = record
    dwServiceType: DWORD;
    dwCurrentState: DWORD;
    dwControlsAccepted: DWORD;
    dwWin32ExitCode: DWORD;
    dwServiceSpecificExitCode: DWORD;
    dwCheckPoint: DWORD;
    dwWaitHint: DWORD;
  end;

  TSvcState = (
    ssUnknown,
    ssNotInstalled,
    ssStopped,
    ssStartPending,
    ssStopPending,
    ssRunning,
    ssContinuePending,
    ssPausePending,
    ssPaused
  );

  TSvcCommand = (scStart, scStop, scInstall, scUninstall);

  TCommandDoneEvent = procedure(Sender: TObject; Cmd: TSvcCommand;
    Success: Boolean; ExitCode: DWORD; const Output: string) of object;

  { TSvcCommandThread
    Runs the "edrsvc.exe <arg>" process, collects the console output and,
    when it finishes, triggers the OnDone event on the main thread via
    Synchronize. FreeOnTerminate=True, so the caller must NOT free the
    object. }
  TSvcCommandThread = class(TThread)
  private
    FExePath: string;
    FArg: string;
    FCmd: TSvcCommand;
    FSuccess: Boolean;
    FExitCode: DWORD;
    FOutput: string;
    FOnDone: TCommandDoneEvent;
    procedure DoSync;
  protected
    procedure Execute; override;
  public
    constructor Create(const AExePath, AArg: string; ACmd: TSvcCommand;
      AOnDone: TCommandDoneEvent);
  end;

function OpenSCManagerW(lpMachineName, lpDatabaseName: PWideChar;
  dwDesiredAccess: DWORD): SC_HANDLE; stdcall; external ADVAPI32_DLL name 'OpenSCManagerW';
function OpenServiceW(hSCManager: SC_HANDLE; lpServiceName: PWideChar;
  dwDesiredAccess: DWORD): SC_HANDLE; stdcall; external ADVAPI32_DLL name 'OpenServiceW';
function QueryServiceStatus(hService: SC_HANDLE;
  var lpServiceStatus: TServiceStatus): BOOL; stdcall; external ADVAPI32_DLL name 'QueryServiceStatus';
function CloseServiceHandle(hSCObject: SC_HANDLE): BOOL; stdcall; external ADVAPI32_DLL name 'CloseServiceHandle';

function GetServiceState(const AServiceName: string): TSvcState;
function SvcStateToStr(AState: TSvcState): string;
function IsServiceInstalled(const AServiceName: string): Boolean;
function ResolveAgentExePath: string;
function CommandToArg(ACmd: TSvcCommand): string;

implementation

function ResolveAgentExePath: string;
var
  sBase: string;
begin
  sBase := ExtractFilePath(ParamStr(0));
  Result := sBase + 'edrsvc.exe';
  if not FileExists(Result) then
    Result := sBase + 'bin' + PathDelim + 'edrsvc.exe';
end;

function CommandToArg(ACmd: TSvcCommand): string;
begin
  case ACmd of
    scStart:     Result := 'start';
    scStop:      Result := 'stop';
    scInstall:   Result := 'install';
    scUninstall: Result := 'uninstall';
  else
    Result := '';
  end;
end;

function IsServiceInstalled(const AServiceName: string): Boolean;
begin
  Result := GetServiceState(AServiceName) <> ssNotInstalled;
end;

function GetServiceState(const AServiceName: string): TSvcState;
var
  hSCM, hSvc: SC_HANDLE;
  Status: TServiceStatus;
begin
  Result := ssUnknown;
  hSCM := OpenSCManagerW(nil, nil, SC_MANAGER_CONNECT);
  if hSCM = 0 then
    Exit(ssUnknown);
  try
    hSvc := OpenServiceW(hSCM, PWideChar(UnicodeString(AServiceName)), SERVICE_QUERY_STATUS);
    if hSvc = 0 then
    begin
      Result := ssNotInstalled;
      Exit;
    end;
    try
      if QueryServiceStatus(hSvc, Status) then
      begin
        case Status.dwCurrentState of
          SERVICE_STOPPED:          Result := ssStopped;
          SERVICE_START_PENDING:    Result := ssStartPending;
          SERVICE_STOP_PENDING:     Result := ssStopPending;
          SERVICE_RUNNING:          Result := ssRunning;
          SERVICE_CONTINUE_PENDING: Result := ssContinuePending;
          SERVICE_PAUSE_PENDING:    Result := ssPausePending;
          SERVICE_PAUSED:           Result := ssPaused;
        else
          Result := ssUnknown;
        end;
      end
      else
        Result := ssUnknown;
    finally
      CloseServiceHandle(hSvc);
    end;
  finally
    CloseServiceHandle(hSCM);
  end;
end;

function SvcStateToStr(AState: TSvcState): string;
begin
  case AState of
    ssNotInstalled:    Result := 'Not installed';
    ssStopped:         Result := 'Stopped';
    ssStartPending:    Result := 'Starting...';
    ssStopPending:     Result := 'Stopping...';
    ssRunning:         Result := 'Running';
    ssContinuePending: Result := 'Continuing...';
    ssPausePending:    Result := 'Pausing...';
    ssPaused:          Result := 'Paused';
  else
    Result := 'Unknown';
  end;
end;

{ TSvcCommandThread }

constructor TSvcCommandThread.Create(const AExePath, AArg: string;
  ACmd: TSvcCommand; AOnDone: TCommandDoneEvent);
begin
  inherited Create(True);
  FreeOnTerminate := True;
  FExePath := AExePath;
  FArg := AArg;
  FCmd := ACmd;
  FOnDone := AOnDone;
  Start;
end;

procedure TSvcCommandThread.Execute;
var
  SecAttr: TSecurityAttributes;
  StdOutRead, StdOutWrite: THandle;
  StartInfo: TStartupInfo;
  ProcInfo: TProcessInformation;
  CmdLine: string;
  Buffer: array[0..4095] of AnsiChar;
  BytesRead: DWORD;
  Output: string;
begin
  FSuccess := False;
  FExitCode := DWORD(-1);
  Output := '';

  if not FileExists(FExePath) then
  begin
    FOutput := 'edrsvc.exe not found: ' + FExePath;
    Synchronize(@DoSync);
    Exit;
  end;

  SecAttr.nLength := SizeOf(TSecurityAttributes);
  SecAttr.bInheritHandle := True;
  SecAttr.lpSecurityDescriptor := nil;

  if not CreatePipe(StdOutRead, StdOutWrite, @SecAttr, 0) then
  begin
    FOutput := 'Could not create pipe (error ' + IntToStr(GetLastError) + ')';
    Synchronize(@DoSync);
    Exit;
  end;
  SetHandleInformation(StdOutRead, HANDLE_FLAG_INHERIT, 0);

  FillChar(StartInfo, SizeOf(StartInfo), 0);
  StartInfo.cb := SizeOf(StartInfo);
  StartInfo.dwFlags := STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW;
  StartInfo.wShowWindow := SW_HIDE;
  StartInfo.hStdOutput := StdOutWrite;
  StartInfo.hStdError := StdOutWrite;

  CmdLine := '"' + FExePath + '" ' + FArg;
  UniqueString(CmdLine);

  if CreateProcess(nil, PChar(CmdLine), nil, nil, True,
      CREATE_NO_WINDOW, nil, PChar(ExtractFilePath(FExePath)),
      StartInfo, ProcInfo) then
  begin
    CloseHandle(StdOutWrite);
    repeat
      if ReadFile(StdOutRead, Buffer, SizeOf(Buffer) - 1, BytesRead, nil)
         and (BytesRead > 0) then
      begin
        Buffer[BytesRead] := #0;
        Output := Output + string(Buffer);
      end
      else
        Break;
    until False;

    WaitForSingleObject(ProcInfo.hProcess, 30000);
    GetExitCodeProcess(ProcInfo.hProcess, FExitCode);
    FSuccess := FExitCode = 0;

    CloseHandle(ProcInfo.hProcess);
    CloseHandle(ProcInfo.hThread);
  end
  else
  begin
    CloseHandle(StdOutWrite);
    Output := 'CreateProcess failed (error ' + IntToStr(GetLastError) + ')';
  end;

  CloseHandle(StdOutRead);
  FOutput := Trim(Output);

  Synchronize(@DoSync);
end;

procedure TSvcCommandThread.DoSync;
begin
  if Assigned(FOnDone) then
    FOnDone(Self, FCmd, FSuccess, FExitCode, FOutput);
end;

end.