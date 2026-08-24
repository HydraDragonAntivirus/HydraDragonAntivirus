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

  { THipPipeConnection - handles a single connected client (one message) }

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

  { THipPipeListener - accepts connections on the HIPS pipe }

  THipPipeListener = class(TThread)
  private
    FOnMessage: THipPipeMessage;
  protected
    procedure Execute; override;
  public
    constructor Create(AOnMessage: THipPipeMessage);
  end;

implementation

uses
  UAlert;

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
begin
  total := 0;
  data := '';
  repeat
    if not ReadFile(FHandle, buf[0], SizeOf(buf), nRead, nil) or (nRead = 0) then
      Break;
    SetLength(data, Length(data) + Integer(nRead));
    Move(buf[0], data[Length(data) - Integer(nRead) + 1], nRead);
    Inc(total, nRead);
    // A message is one line: break only when newline (#10) is received
    if Pos(#10, data) > 0 then
      Break;
  until False;

  data := Trim(data);
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

    if (Trim(FKind) <> '') and (Trim(FText) <> '') then
      Synchronize(@DoNotify);
  end;

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
      PIPE_ACCESS_INBOUND,
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

    // Small pause so the loop yields CPU while waiting for clients.
    Sleep(20);
  end;
end;

end.