unit UHipPipe;

{ ---------------------------------------------------------------------------
  UHipPipe
  ---------------------------------------------------------------------------
  Named-pipe SERVER for the HIPS/GUI notification channel `\\.\pipe\HydraHipEvent`.

  The Rust behavior engine (owlyshield_predict) writes short newline-terminated
  messages to this pipe for the firewall GUI:

    THREAT_ALERT:<threat_name>|<file_path>
    HIPS_ASK:<request_id>|<pid>|<app_name>|<exe_path>|<alert_kind>|<target>|<reason>
    HIPS_VERDICT:<pid>|<exe_path>|<verdict_code>|<analysis_type>

  This unit listens on that pipe and raises a toast via TAlertForm for every
  message. All callbacks run on the main thread through Synchronize().

  Author: Emirhan Ucan (20.08.2026)
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Windows;

const
  HIPS_PIPE_NAME = '\\.\pipe\HydraHipEvent';
  PIPE_UNLIMITED_INSTANCES = 255;

type
  THipPipeMessage = procedure(Sender: TObject; const AKind, AText: string) of object;

  { THipPipeConnection - handles a single connected client }

  THipPipeConnection = class(TThread)
  private
    FHandle: THandle;
    FOnMessage: THipPipeMessage;
    FKind: string;
    FText: string;
    procedure DoNotify;
  protected
    procedure Execute; override;
  public
    constructor Create(AHandle: THandle; AOnMessage: THipPipeMessage);
  end;

  { THipPipeListener - accepts duplex connections on the HIPS pipe }

  THipPipeListener = class(TThread)
  private
    FOnMessage: THipPipeMessage;
  protected
    procedure Execute; override;
  public
    constructor Create(AOnMessage: THipPipeMessage);
  end;

function SendHipDecision(const ARequestId, ADecision, AExePath: string): Boolean;

implementation

uses
  UAlert;

type
  TPendingPrompt = record
    RequestId: string;
    PipeHandle: THandle;
  end;

var
  PendingPrompts: array of TPendingPrompt;
  PendingCS: TRTLCriticalSection;

procedure InitPendingCS;
begin
  InitCriticalSection(PendingCS);
end;

procedure DonePendingCS;
begin
  DoneCriticalSection(PendingCS);
end;

procedure RegisterPendingPrompt(const ARequestId: string; AHandle: THandle);
var
  i, n: Integer;
begin
  EnterCriticalSection(PendingCS);
  try
    n := Length(PendingPrompts);
    for i := 0 to n - 1 do
      if PendingPrompts[i].RequestId = ARequestId then
      begin
        PendingPrompts[i].PipeHandle := AHandle;
        Exit;
      end;
    SetLength(PendingPrompts, n + 1);
    PendingPrompts[n].RequestId := ARequestId;
    PendingPrompts[n].PipeHandle := AHandle;
  finally
    LeaveCriticalSection(PendingCS);
  end;
end;

function TakePendingPromptHandle(const ARequestId: string): THandle;
var
  i, n: Integer;
begin
  Result := INVALID_HANDLE_VALUE;
  EnterCriticalSection(PendingCS);
  try
    n := Length(PendingPrompts);
    for i := 0 to n - 1 do
      if PendingPrompts[i].RequestId = ARequestId then
      begin
        Result := PendingPrompts[i].PipeHandle;
        // Swap with last
        PendingPrompts[i] := PendingPrompts[n - 1];
        SetLength(PendingPrompts, n - 1);
        Exit;
      end;
  finally
    LeaveCriticalSection(PendingCS);
  end;
end;

function SendHipDecision(const ARequestId, ADecision, AExePath: string): Boolean;
var
  hPipe, hDrvPipe: THandle;
  msg, killMsg: UTF8String;
  written: DWORD;
  RulesFile, pidStr: string;
  F: TextFile;
  RulesJson: string;
  parts: TStringList;
begin
  Result := False;
  hPipe := TakePendingPromptHandle(ARequestId);
  msg := 'HIPS_DECISION:' + ARequestId + '|' + ADecision + #10;

  if (hPipe <> 0) and (hPipe <> INVALID_HANDLE_VALUE) then
  begin
    WriteFile(hPipe, msg[1], Length(msg), written, nil);
    FlushFileBuffers(hPipe);
    CloseHandle(hPipe);
    Result := True;
  end;

  // Signal C++ Sysmon Controller to execute Ring-0 kernel driver kill immediately
  if (ADecision = 'block') or (ADecision = 'quarantine') then
  begin
    hDrvPipe := CreateFileW('\\.\pipe\HydraHipDecision',
      GENERIC_WRITE, 0, nil, OPEN_EXISTING, 0, 0);
    if (hDrvPipe <> 0) and (hDrvPipe <> INVALID_HANDLE_VALUE) then
    begin
      // Extract PID from RequestId (format: ask_<PID>_<TIMESTAMP>)
      pidStr := '0';
      parts := TStringList.Create;
      try
        parts.Delimiter := '_';
        parts.StrictDelimiter := True;
        parts.DelimitedText := ARequestId;
        if parts.Count >= 2 then
          pidStr := parts[1];
      finally
        parts.Free;
      end;

      killMsg := 'HIPS_KILL:' + pidStr + '|' + ADecision + '|' + AExePath + #10;
      WriteFile(hDrvPipe, killMsg[1], Length(killMsg), written, nil);
      CloseHandle(hDrvPipe);
    end;
  end;

  // Persist permanent decisions to C:\ProgramData\edrsvc\firewall_rules.json
  if (ADecision = 'allow_always') or (ADecision = 'block') then
  begin
    RulesFile := 'C:\ProgramData\edrsvc\firewall_rules.json';
    try
      ForceDirectories(ExtractFilePath(RulesFile));
      // Append entry or write timestamped rule
      AssignFile(F, RulesFile);
      if FileExists(RulesFile) then
        Append(F)
      else
        Rewrite(F);
      WriteLn(F, Format('{"action":"%s","path":"%s","time":"%s"}',
        [ADecision, StringReplace(AExePath, '\', '\\', [rfReplaceAll]),
         DateTimeToStr(Now)]));
      CloseFile(F);
    except
      // Ignore write errors if service currently locks it
    end;
  end;
end;

{ THipPipeConnection }

constructor THipPipeConnection.Create(AHandle: THandle; AOnMessage: THipPipeMessage);
begin
  inherited Create(False);
  FHandle := AHandle;
  FOnMessage := AOnMessage;
  FreeOnTerminate := True;
end;

procedure THipPipeConnection.DoNotify;
begin
  if Assigned(FOnMessage) then
    FOnMessage(Self, FKind, FText);
end;

procedure THipPipeConnection.Execute;
var
  buf: array[0..4095] of Byte;
  nRead, total: DWORD;
  data: string;
  i: Integer;
  IsAskPrompt: Boolean;
  ReqId: string;
  parts: TStringList;
begin
  total := 0;
  data := '';
  repeat
    if not ReadFile(FHandle, buf[0], SizeOf(buf), nRead, nil) or (nRead = 0) then
      Break;
    SetLength(data, Length(data) + Integer(nRead));
    Move(buf[0], data[Length(data) - Integer(nRead) + 1], nRead);
    Inc(total, nRead);
    if Pos(#10, data) > 0 then
      Break;
  until False;

  data := Trim(data);
  IsAskPrompt := False;
  if data <> '' then
  begin
    i := Pos(':', data);
    if i > 0 then
    begin
      FKind := Trim(Copy(data, 1, i - 1));
      FText := Trim(Copy(data, i + 1, MaxInt));
    end
    else
    begin
      FKind := 'HIPS';
      FText := data;
    end;

    if FKind = 'HIPS_ASK' then
    begin
      IsAskPrompt := True;
      // Extract RequestId (first field before '|')
      i := Pos('|', FText);
      if i > 0 then
        ReqId := Copy(FText, 1, i - 1)
      else
        ReqId := FText;
      RegisterPendingPrompt(ReqId, FHandle);
    end;

    if (Trim(FKind) <> '') and (Trim(FText) <> '') then
      Synchronize(@DoNotify);
  end;

  // If this was an ask prompt, keep handle open until SendHipDecision responds!
  if not IsAskPrompt then
    CloseHandle(FHandle);
end;

{ THipPipeListener }

constructor THipPipeListener.Create(AOnMessage: THipPipeMessage);
begin
  inherited Create(False);
  FOnMessage := AOnMessage;
  FreeOnTerminate := True;
end;

procedure THipPipeListener.Execute;
var
  hPipe: THandle;
begin
  while not Terminated do
  begin
    hPipe := CreateNamedPipeA(
      PAnsiChar(HIPS_PIPE_NAME),
      PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_MESSAGE or PIPE_READMODE_MESSAGE or PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      4096,
      4096,
      0,
      nil);

    if hPipe = INVALID_HANDLE_VALUE then
    begin
      Sleep(500);
      Continue;
    end;

    if ConnectNamedPipe(hPipe, nil) or (GetLastError = ERROR_PIPE_CONNECTED) then
      THipPipeConnection.Create(hPipe, FOnMessage)
    else
      CloseHandle(hPipe);

    Sleep(20);
  end;
end;

initialization
  InitPendingCS;

finalization
  DonePendingCS;

end.