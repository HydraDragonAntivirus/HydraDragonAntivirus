unit UScan;

{ ---------------------------------------------------------------------------
  UScan / TScanForm - on-demand static file scanner screen.
  ---------------------------------------------------------------------------
  UI shell only: all verdicts come from the engines.
  - Rust  : owlyshield_scan_file  (EICAR hash, malicious/PUA vendor signer,
            trusted signer) via LoadLibrary, no service needed.
  - C++   : checkFileKnown / quarantineFile JSON-RPC on 127.0.0.1:5890
            (known-malware DB lookup incl. content hash, quarantine with
            DB record so later restores stay blocked).
  Kernel-watcher auto-scan is intentionally NOT used here: the driver scan
  directory list is currently inert (same write-only class of bug as the
  kernel block list was). Manual directory walk generates the file activity
  the existing pipeline already watches.
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, StdCtrls, ComCtrls, Dialogs, Windows,
  fpjson, jsonparser, UGuiNotify, UAlert;

type
  TScanForm = class; // forward: TScanThread references the form below

  TScanVerdict = (svUnknown, svSafe, svMalicious, svKnown);

  TScanFileFn = function(APath: PWideChar; ALen: Cardinal): Integer; cdecl;

  { TScanThread }

  TScanThread = class(TThread)
  private
    FRoot: WideString;
    FForm: TScanForm;
    FScanFn: TScanFileFn;
    FOnePath: string;
    FOneVerdict: TScanVerdict;
    FOneDetail: string;
    FCount: Integer;
    procedure PushOne;
    procedure Walk(const ADir: WideString);
    procedure ScanOneFile(const APath: WideString);
    function RpcCheckKnown(const APathUtf8: string; out AHash: string): Boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(AScanForm: TScanForm; const ARoot: WideString; AScanFn: TScanFileFn);
  end;

  { TScanForm }

  TScanForm = class(TForm)
    TitleLbl: TLabel;
    PathEdit: TEdit;
    BrowseBtn: TButton;
    StartBtn: TButton;
    CancelBtn: TButton;
    QuarBtn: TButton;
    ScanProgress: TProgressBar;
    StatusLbl: TLabel;
    SummaryLbl: TLabel;
    ResultsView: TListView;
    procedure BrowseBtnClick(Sender: TObject);
    procedure StartBtnClick(Sender: TObject);
    procedure CancelBtnClick(Sender: TObject);
    procedure QuarBtnClick(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    FDll: HMODULE;
    FScanFn: TScanFileFn;
    FThread: TScanThread;
    FMali, FKnown, FSafe, FUnk, FQuar: Integer;
    function LoadEngine: Boolean;
    procedure UnloadEngine;
    procedure ThreadDone(Sender: TObject);
    function RpcQuarantine(const APathUtf8: string): Boolean;
    function VerdictText(V: TScanVerdict): string;
  public
  end;

function EscapeJson(const S: string): string;

implementation

{$R *.lfm}

function EscapeJson(const S: string): string;
var
  i: Integer;
  c: Char;
begin
  Result := '';
  for i := 1 to Length(S) do
  begin
    c := S[i];
    case c of
      '"': Result := Result + '\"';
      '\': Result := Result + '\\';
      #8: Result := Result + '\b';
      #9: Result := Result + '\t';
      #10: Result := Result + '\n';
      #12: Result := Result + '\f';
      #13: Result := Result + '\r';
    else
      if Ord(c) < 32 then
        Result := Result + '\u' + IntToHex(Ord(c), 4)
      else
        Result := Result + c;
    end;
  end;
end;

{ TScanThread }

constructor TScanThread.Create(AScanForm: TScanForm; const ARoot: WideString; AScanFn: TScanFileFn);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FForm := AScanForm;
  FRoot := ARoot;
  FScanFn := AScanFn;
end;

function TScanThread.RpcCheckKnown(const APathUtf8: string; out AHash: string): Boolean;
var
  Req, Resp: string;
  j, d: TJSONData;
begin
  Result := False;
  AHash := '';
  try
    Req := '{"jsonrpc":"2.0","id":1,"method":"checkFileKnown","params":{"path":"' +
      EscapeJson(APathUtf8) + '"}}';
    if HttpPostJson(GUI_RPC_HOST, GUI_RPC_PORT, Req, Resp) then
    begin
      j := GetJSON(Resp);
      try
        d := j.FindPath('result.known');
        Result := (d <> nil) and d.AsBoolean;
        d := j.FindPath('result.hash');
        if d <> nil then
          AHash := d.AsString;
      finally
        j.Free;
      end;
    end;
  except
    Result := False;
  end;
end;

procedure TScanThread.PushOne;
var
  Item: TListItem;
  Frm: TScanForm;
begin
  Frm := FForm;
  if (Frm = nil) or (Frm.ResultsView = nil) then
    Exit;
  Item := Frm.ResultsView.Items.Add;
  Item.Caption := FOnePath;
  case FOneVerdict of
    svMalicious: Item.SubItems.Add('Malicious');
    svKnown: Item.SubItems.Add('Known threat');
    svSafe: Item.SubItems.Add('Safe');
  else
    Item.SubItems.Add('Unknown');
  end;
  Item.SubItems.Add(FOneDetail);
  Item.Data := Pointer(PtrInt(Ord(FOneVerdict)));
  case FOneVerdict of
    svMalicious: InterlockedIncrement(Frm.FMali);
    svKnown: InterlockedIncrement(Frm.FKnown);
    svSafe: InterlockedIncrement(Frm.FSafe);
  else
    InterlockedIncrement(Frm.FUnk);
  end;
  Inc(FCount);
  if (FCount mod 25) = 0 then
    Frm.StatusLbl.Caption := 'Scanned ' + IntToStr(FCount) + ' files...';
end;

procedure TScanThread.ScanOneFile(const APath: WideString);
var
  v: Integer;
  h: string;
  u8: string;
begin
  if Terminated then
    Exit;
  u8 := UTF8Encode(APath);
  FOnePath := u8;
  FOneVerdict := svUnknown;
  FOneDetail := '';
  if Assigned(FScanFn) then
  begin
    v := FScanFn(PWideChar(APath), Cardinal(Length(APath)));
    if v = 2 then
    begin
      FOneVerdict := svMalicious;
      FOneDetail := 'Static indicator (EICAR/signer)';
    end
    else if v = 1 then
    begin
      FOneVerdict := svSafe;
      FOneDetail := 'Trusted signer';
    end;
  end;
  if (FOneVerdict = svUnknown) and RpcCheckKnown(u8, h) then
  begin
    FOneVerdict := svKnown;
    FOneDetail := 'Known-malware database';
  end;
  Synchronize(@PushOne);
end;

procedure TScanThread.Walk(const ADir: WideString);
var
  h: THandle;
  fd: TWin32FindDataW;
  nm, p: WideString;
begin
  h := FindFirstFileW(PWideChar(ADir + WideString('*')), fd);
  if h = INVALID_HANDLE_VALUE then
    Exit;
  try
    repeat
      if Terminated then
        Exit;
      nm := WideString(fd.cFileName);
      if (nm = WideString('.')) or (nm = WideString('..')) then
        Continue;
      p := ADir + nm;
      if (fd.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) <> 0 then
      begin
        if (fd.dwFileAttributes and FILE_ATTRIBUTE_REPARSE_POINT) = 0 then
          Walk(p + WideString('\'));
      end
      else
        ScanOneFile(p);
    until not FindNextFileW(h, fd);
  finally
    Windows.FindClose(h);
  end;
end;

procedure TScanThread.Execute;
begin
  FCount := 0;
  Walk(FRoot);
end;

{ TScanForm }

function TScanForm.VerdictText(V: TScanVerdict): string;
begin
  case V of
    svMalicious: Result := 'Malicious';
    svKnown: Result := 'Known threat';
    svSafe: Result := 'Safe';
  else
    Result := 'Unknown';
  end;
end;

function TScanForm.LoadEngine: Boolean;
var
  DllPath: WideString;
begin
  Result := Assigned(FScanFn);
  if Result then
    Exit;
  if FDll = 0 then
  begin
    DllPath := WideString(ExtractFilePath(ParamStr(0)) + 'owlyshield_ransom.dll');
    FDll := LoadLibraryW(PWideChar(DllPath));
    if FDll = 0 then
      FDll := LoadLibraryW(PWideChar(WideString('owlyshield_ransom.dll')));
  end;
  if FDll <> 0 then
    FScanFn := TScanFileFn(GetProcAddress(FDll, 'owlyshield_scan_file'));
  Result := Assigned(FScanFn);
end;

procedure TScanForm.UnloadEngine;
begin
  FScanFn := nil;
  if FDll <> 0 then
  begin
    FreeLibrary(FDll);
    FDll := 0;
  end;
end;

procedure TScanForm.BrowseBtnClick(Sender: TObject);
var
  Dir: string;
begin
  Dir := Trim(PathEdit.Text);
  if SelectDirectory(Dir, [sdAllowCreate], 0) then
    PathEdit.Text := Dir;
end;

procedure TScanForm.StartBtnClick(Sender: TObject);
var
  Root: WideString;
begin
  if FThread <> nil then
    Exit;
  Root := WideString(Trim(PathEdit.Text));
  if (Root = '') or
    (GetFileAttributesW(PWideChar(Root)) = INVALID_FILE_ATTRIBUTES) or
    ((GetFileAttributesW(PWideChar(Root)) and FILE_ATTRIBUTE_DIRECTORY) = 0) then
  begin
    TAlertForm.ShowAlert('Scanner', 'Pick an existing folder first.',
      asWarning, 3000);
    Exit;
  end;
  if Root[Length(Root)] <> WideChar('\') then
    Root := Root + '\';
  if not LoadEngine then
    TAlertForm.ShowAlert('Scanner',
      'Static engine unavailable (owlyshield_ransom.dll). Only known-DB checks will run.',
      asWarning, 4000);
  ResultsView.Items.Clear;
  FMali := 0;
  FKnown := 0;
  FSafe := 0;
  FUnk := 0;
  FQuar := 0;
  SummaryLbl.Caption := '';
  ScanProgress.Style := pbstMarquee;
  StartBtn.Enabled := False;
  CancelBtn.Enabled := True;
  QuarBtn.Enabled := False;
  FThread := TScanThread.Create(Self, Root, FScanFn);
  FThread.OnTerminate := @ThreadDone;
  FThread.Start;
end;

procedure TScanForm.CancelBtnClick(Sender: TObject);
begin
  if FThread <> nil then
    FThread.Terminate;
  StatusLbl.Caption := 'Cancelling...';
end;

procedure TScanForm.ThreadDone(Sender: TObject);
begin
  FreeAndNil(FThread);
  ScanProgress.Style := pbstNormal;
  StartBtn.Enabled := True;
  CancelBtn.Enabled := False;
  QuarBtn.Enabled := (FMali + FKnown) > 0;
  StatusLbl.Caption := 'Done.';
  SummaryLbl.Caption := Format(
    'Malicious: %d, Known: %d, Safe: %d, Unknown: %d, Quarantined: %d',
    [FMali, FKnown, FSafe, FUnk, FQuar]);
end;

function TScanForm.RpcQuarantine(const APathUtf8: string): Boolean;
var
  Req, Resp: string;
  j, d: TJSONData;
begin
  Result := False;
  try
    Req := '{"jsonrpc":"2.0","id":1,"method":"quarantineFile","params":{"path":"' +
      EscapeJson(APathUtf8) + '"}}';
    if HttpPostJson(GUI_RPC_HOST, GUI_RPC_PORT, Req, Resp) then
    begin
      j := GetJSON(Resp);
      try
        d := j.FindPath('result.success');
        Result := (d <> nil) and d.AsBoolean;
      finally
        j.Free;
      end;
    end;
  except
    Result := False;
  end;
end;

procedure TScanForm.QuarBtnClick(Sender: TObject);
var
  i, n: Integer;
  p: string;
begin
  n := 0;
  for i := 0 to ResultsView.Items.Count - 1 do
  begin
    if not ResultsView.Items[i].Selected then
      Continue;
    case TScanVerdict(PtrInt(ResultsView.Items[i].Data)) of
      svMalicious, svKnown:
        begin
          p := ResultsView.Items[i].Caption;
          if RpcQuarantine(p) then
          begin
            ResultsView.Items[i].SubItems[1] :=
              ResultsView.Items[i].SubItems[1] + ' [quarantined]';
            Inc(n);
            InterlockedIncrement(FQuar);
          end;
        end;
    end;
  end;
  TAlertForm.ShowAlert('Scanner', IntToStr(n) + ' file(s) quarantined.',
    asSuccess, 4000);
  SummaryLbl.Caption := Format(
    'Malicious: %d, Known: %d, Safe: %d, Unknown: %d, Quarantined: %d',
    [FMali, FKnown, FSafe, FUnk, FQuar]);
end;

procedure TScanForm.FormDestroy(Sender: TObject);
begin
  if FThread <> nil then
  begin
    FThread.Terminate;
    FThread.WaitFor;
    FreeAndNil(FThread);
  end;
  UnloadEngine;
end;

end.
