unit UGuiNotify;

{ ---------------------------------------------------------------------------
  UGuiNotify
  ---------------------------------------------------------------------------
  Receives malicious-file detections from the local edrsvc daemon and raises
  a toast via TAlertForm.

  The daemon exposes a JSON-RPC server on 127.0.0.1:5890 (plain channel,
  see edrsvc.cfg "guiRpcServer"). This unit polls the "getDetections"
  command from a background thread and pushes new events to the caller on
  the main thread through Synchronize().

  Author: Emirhan Ucan (20.08.2026)
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, WinSock, fpjson, jsonparser;

const
  GUI_RPC_HOST = '127.0.0.1';
  GUI_RPC_PORT = 5890;
  GUI_RPC_POLL_INTERVAL_MS = 2000;

type
  TDetInfo = record
    Id: Int64;
    Title: string;
    EventType: string;
    ImagePath: string;
    AttackChain: string;
    FlsVerdict: Integer;
    Verdict: Integer;
  end;
  TDetInfoArray = array of TDetInfo;

  TOnDetections = procedure(Sender: TObject; const Detections: TDetInfoArray) of object;

  { TGuiNotifierThread }

  TGuiNotifierThread = class(TThread)
  private
    FHost: string;
    FPort: Word;
    FIntervalMs: Cardinal;
    FLastId: Int64;
    FOnDetections: TOnDetections;
    FDetections: TDetInfoArray;
    procedure DoNotify;
  protected
    procedure Execute; override;
  public
    constructor Create(AOnDetections: TOnDetections);
    property Host: string read FHost write FHost;
    property Port: Word read FPort write FPort;
    property IntervalMs: Cardinal read FIntervalMs write FIntervalMs;
  end;

  // Performs a single HTTP POST carrying a JSON-RPC request and returns the
  // response body (plain text after the HTTP headers). Returns False on any
  // transport error. Public so it can be reused for diagnostics.
  function HttpPostJson(const AHost: string; APort: Word;
    const ARequest: string; out AResponse: string): Boolean;

implementation

var
  WSAStarted: Boolean = False;

function EnsureWSA: Boolean;
var
  wd: TWSAData;
begin
  if not WSAStarted then
    WSAStarted := (WSAStartup($0101, wd) = 0);
  Result := WSAStarted;
end;

procedure ShutdownWSA;
begin
  if WSAStarted then
  begin
    WSACleanup;
    WSAStarted := False;
  end;
end;

function HttpPostJson(const AHost: string; APort: Word;
  const ARequest: string; out AResponse: string): Boolean;
var
  s: TSocket;
  addr: TSockAddrIn;
  Body, Req: UTF8String;
  buf: array[0..8191] of Byte;
  n, Off: Integer;
  Resp: string;
  PosHdr: Integer;
begin
  Result := False;
  AResponse := '';

  if not EnsureWSA then
    Exit;

  s := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if s = INVALID_SOCKET then
    Exit;

  try
    FillChar(addr, SizeOf(addr), 0);
    addr.sin_family := AF_INET;
    addr.sin_port := htons(APort);
    addr.sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(AHost)));

    if connect(s, TSockAddr(addr), SizeOf(addr)) <> 0 then
      Exit;

    Body := UTF8Encode(ARequest);
    Req := 'POST / HTTP/1.1'#13#10 +
           'Host: ' + AnsiString(AHost) + ':' + IntToStr(APort) + #13#10 +
           'Content-Type: application/json'#13#10 +
           'Content-Length: ' + IntToStr(Length(Body)) + #13#10 +
           'Connection: close'#13#10#13#10 + Body;

    Off := 1;
    while Off <= Length(Req) do
    begin
      n := send(s, Req[Off], Length(Req) - Off + 1, 0);
      if n <= 0 then
        Exit;
      Inc(Off, n);
    end;

    Resp := '';
    repeat
      n := recv(s, buf[0], SizeOf(buf), 0);
      if n <= 0 then
        Break;
      SetLength(Resp, Length(Resp) + n);
      Move(buf[0], Resp[Length(Resp) - n + 1], n);
    until False;

    PosHdr := Pos(#13#10#13#10, Resp);
    if PosHdr <= 0 then
      Exit;

    AResponse := Copy(Resp, PosHdr + 4, MaxInt);
    Result := True;
  finally
    closesocket(s);
  end;
end;

function GetPathStr(j: TJSONData; const APath: string): string;
var
  d: TJSONData;
begin
  d := j.FindPath(APath);
  if d = nil then
    Result := ''
  else
    Result := d.AsString;
end;

function GetPathInt(j: TJSONData; const APath: string): Integer;
var
  d: TJSONData;
begin
  d := j.FindPath(APath);
  if d = nil then
    Result := 0
  else
    Result := d.AsInteger;
end;

{ TGuiNotifierThread }

constructor TGuiNotifierThread.Create(AOnDetections: TOnDetections);
begin
  inherited Create(False);
  FHost := GUI_RPC_HOST;
  FPort := GUI_RPC_PORT;
  FIntervalMs := GUI_RPC_POLL_INTERVAL_MS;
  FLastId := 0;
  FOnDetections := AOnDetections;
  FreeOnTerminate := True;
end;

procedure TGuiNotifierThread.DoNotify;
begin
  if Assigned(FOnDetections) then
    FOnDetections(Self, FDetections);
end;

procedure TGuiNotifierThread.Execute;
var
  j: TJSONData;
  jEvents, jProcs: TJSONArray;
  jEvent, jProc: TJSONData;
  Req, Resp: string;
  i, n, k: Integer;
  Det: TDetInfo;
  ProcChain: string;
begin
  if not EnsureWSA then
    Exit;

  // On initial startup, sync FLastId to current daemon lastId to avoid replaying old events
  try
    Req := '{"jsonrpc":"2.0","id":1,"method":"getLastDetectionId","params":{}}';
    if HttpPostJson(FHost, FPort, Req, Resp) then
    begin
      j := GetJSON(Resp);
      try
        FLastId := GetPathInt(j, 'result.lastId');
      finally
        j.Free;
      end;
    end;
  except
  end;

  try
    while not Terminated do
    begin
      try
        Req := '{"jsonrpc":"2.0","id":1,"method":"getDetections",' +
               '"params":{"lastId":' + IntToStr(FLastId) + '}}';

        if HttpPostJson(FHost, FPort, Req, Resp) then
        begin
          j := GetJSON(Resp);
          try
            n := 0;
            jEvents := j.FindPath('result.events') as TJSONArray;
            if jEvents <> nil then
            begin
              for i := 0 to jEvents.Count - 1 do
              begin
                jEvent := jEvents.Items[i];
                if jEvent = nil then
                  Continue;
                Det.Id := GetPathInt(jEvent, 'id');
                jEvent := jEvent.FindPath('event');
                if jEvent = nil then
                  Continue;

                Det.EventType := GetPathStr(jEvent, 'type');
                Det.ImagePath := GetPathStr(jEvent, 'quarantineTarget');
                if Det.ImagePath = '' then
                begin
                  Det.ImagePath := GetPathStr(jEvent, 'processes[0].imagePath');
                  if Det.ImagePath = '' then
                    Det.ImagePath := GetPathStr(jEvent, 'childProcess.imagePath');
                end;

                ProcChain := '';
                jProcs := jEvent.FindPath('processes') as TJSONArray;
                if jProcs <> nil then
                begin
                  for k := 0 to jProcs.Count - 1 do
                  begin
                    jProc := jProcs.Items[k];
                    if jProc <> nil then
                    begin
                      if ProcChain <> '' then
                        ProcChain := ProcChain + ' -> '#13#10'  ';
                      ProcChain := ProcChain + ExtractFileName(GetPathStr(jProc, 'imagePath'));
                    end;
                  end;
                end;
                Det.AttackChain := ProcChain;

                Det.Title := GetPathStr(jEvent, 'title');
                Det.FlsVerdict := GetPathInt(jEvent, 'processes[0].flsVerdict');
                Det.Verdict := GetPathInt(jEvent, 'processes[0].verdict');
                if Det.EventType = '' then
                  Det.EventType := IntToStr(GetPathInt(jEvent, 'baseType'));

                SetLength(FDetections, n + 1);
                FDetections[n] := Det;
                Inc(n);

                if Det.Id > FLastId then
                  FLastId := Det.Id;
              end;
            end;

            if n > 0 then
              Synchronize(@DoNotify)
            else
              FLastId := GetPathInt(j, 'result.lastId');
          finally
            j.Free;
          end;
        end;
      except
        // Transient connection/parse errors must never kill the poller.
      end;

      if Terminated then
        Break;
      Sleep(FIntervalMs);
    end;
  finally
    ShutdownWSA;
  end;
end;

end.