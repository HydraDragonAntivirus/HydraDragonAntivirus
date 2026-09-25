unit UScan;

{ ---------------------------------------------------------------------------
  UScan / TScanForm - on-demand scanner screen (NATIVE Windows UI).
  ---------------------------------------------------------------------------
  Trigger-only design, dumb UI shell:
  - FILES mode: worker walks the picked folder and TOUCHES every file
    (open + read head bytes, never executes).
  - REGISTRY mode: worker reads every value of the given key (or of every
    direct subkey with a trailing \*), cleans each referenced executable
    path and TOUCHES the file.
  The kernel watcher turns this activity into telemetry; the existing
  pipeline (rules, FLS, quarantine, rollback) does everything automatically.
  This form only DISPLAYS pipeline detections: it snapshots
  getLastDetectionId at start and polls getDetections for new arrivals.
    Screen controls are defined by the Lazarus form resource.
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, StdCtrls, ComCtrls, Dialogs,
  ExtCtrls, Windows, LCLType, Registry, fpjson, jsonparser, UGuiNotify, UAlert;

type
  TScanForm = class; // forward: worker thread references the form

  TScanMode = (smFiles, smRegistry);

  TScanVerdict = (svUnknown, svSafe, svMalicious, svKnown);

  { owlyshield_scan_file: UTF-16 path + WCHAR count -> 2=malicious, 1=safe,
    0=unknown, -1=bad args. Thin forwarder to openedr_static_scan_file
    (openedr_static.dll), resolved via owlyshield_ransom.dll. }
  TScanFileFn = function(APath: PWideChar; ALen: Cardinal): Integer; cdecl;

  { TScanTouchThread - touches files so the watcher sees them AND direct-scans
    each file with openedr_static (via owlyshield forwarder) so on-demand
    results never depend on the driver/service pipeline alone. }

  TScanTouchThread = class(TThread)
  private
    FForm: TScanForm;
    FMode: TScanMode;
    FRoot: WideString;
    FCount: Integer;
    FScanFn: TScanFileFn;
    FOnePath: string;
    FOneVerdict: TScanVerdict;
    FOneDetail: string;
    procedure PushProgress;
    procedure PushOne;
    procedure Walk(const ADir: WideString);
    procedure TouchOne(const APath: WideString);
    procedure ScanOneFile(const APath: WideString);
    function RpcCheckKnown(const APathUtf8: string; out AHash: string): Boolean;
    procedure ScanRegTarget(const ATarget: WideString);
    procedure ScanRegKey(ARoot: HKEY; const AKey: WideString);
  protected
    procedure Execute; override;
  public
    constructor Create(AScanForm: TScanForm; AMode: TScanMode;
      const ARoot: WideString; AScanFn: TScanFileFn);
  end;

  { TScanForm }

  TScanForm = class(TForm)
  published
    HeaderPnl: TPanel;
    HeaderAccent: TPanel;
    TitleLbl: TLabel;
    SubtitleLbl: TLabel;
    TargetSurface: TPanel;
    ScanSurface: TPanel;
    ResultsSurface: TPanel;
    TargetSectionLbl: TLabel;
    ScanSectionLbl: TLabel;
    ResultsSectionLbl: TLabel;
    RbFiles: TRadioButton;
    RbReg: TRadioButton;
    PathEdit: TEdit;
    BrowseBtn: TButton;
    StartBtn: TButton;
    CancelBtn: TButton;
    ScanProgress: TProgressBar;
    StatusLbl: TLabel;
    SummaryLbl: TLabel;
    ResultsView: TListView;
    PollTimer: TTimer;
    procedure TargetKindChanged(Sender: TObject);
    procedure BrowseBtnClick(Sender: TObject);
    procedure StartBtnClick(Sender: TObject);
    procedure CancelBtnClick(Sender: TObject);
    procedure PollTick(Sender: TObject);
    procedure ResultsDrawItem(Sender: TCustomListView; Item: TListItem;
      State: TCustomDrawState; var DefaultDraw: Boolean);
    procedure FormShowed(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    FThread: TScanTouchThread;
    FDll: HMODULE;
    FScanFn: TScanFileFn;
    FLastId: Int64;
    FFirstShow: Boolean;
    FDetections: Integer;
    FMali, FKnown, FSafe, FUnk: Integer;
    function LoadEngine: Boolean;
    procedure UnloadEngine;
    procedure TouchDone(Sender: TObject);
    procedure RenderNewDetections;
    procedure FinishScan(const AMsg: string);
    function VerdictText(V: TScanVerdict): string;
  protected
    procedure CreateParams(var Params: TCreateParams); override;
  public
    constructor Create(AOwner: TComponent); override;
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

// Unicode-exact registry string read (TRegistry string helpers are ANSI).
function ReadRegStringW(ARoot: HKEY; const AKey, AValue: WideString;
  out S: WideString): Boolean;
var
  h: HKEY;
  typ, sz: DWORD;
  buf: array of WideChar;
begin
  Result := False;
  S := '';
  if RegOpenKeyExW(ARoot, PWideChar(AKey), 0, KEY_READ, h) <> ERROR_SUCCESS then
    Exit;
  try
    typ := 0;
    sz := 0;
    if (RegQueryValueExW(h, PWideChar(AValue), nil, @typ, nil, @sz) <> ERROR_SUCCESS) or
      (sz = 0) or (sz > 65536) then
      Exit;
    if (typ <> REG_SZ) and (typ <> REG_EXPAND_SZ) then
      Exit;
    SetLength(buf, sz div SizeOf(WideChar) + 1);
    if RegQueryValueExW(h, PWideChar(AValue), nil, @typ, PByte(@buf[0]), @sz) <> ERROR_SUCCESS then
      Exit;
    buf[High(buf)] := #0;
    S := WideString(PWideChar(@buf[0]));
    Result := S <> '';
  finally
    RegCloseKey(h);
  end;
end;

function ExpandEnvW(const S: WideString): WideString;
var
  n: DWORD;
begin
  Result := S;
  if S = '' then
    Exit;
  n := ExpandEnvironmentStringsW(PWideChar(S), nil, 0);
  if n <= 1 then
    Exit;
  SetLength(Result, n - 1);
  if ExpandEnvironmentStringsW(PWideChar(S), PWideChar(Result), n) = 0 then
    Result := S;
end;

function CleanExePath(const Cmd: WideString): WideString;
var
  s, low: WideString;
  q, i: Integer;
  sysDir: array[0..260] of WideChar;
begin
  Result := '';
  s := Trim(Cmd);
  if s = '' then
    Exit;
  if s[1] = '"' then
  begin
    q := 0;
    for i := 2 to Length(s) do
      if s[i] = '"' then
      begin
        q := i;
        Break;
      end;
    if q > 2 then
      s := Copy(s, 2, q - 2)
    else
      s := Copy(s, 2, Length(s));
  end
  else
  begin
    i := 1;
    while (i <= Length(s)) and (s[i] <> ' ') and (s[i] <> #9) do
      Inc(i);
    s := Copy(s, 1, i - 1);
  end;
  s := Trim(s);
  if (s <> '') and ((s[Length(s)] = ',') or (s[Length(s)] = ';')) then
    s := Trim(Copy(s, 1, Length(s) - 1));
  if (Length(s) >= 4) and (Copy(s, 1, 4) = '\??\') then
    Delete(s, 1, 4);
  s := ExpandEnvW(s);
  low := LowerCase(s);
  if (Pos(':', s) = 0) and (Copy(s, 1, 2) <> '\\') then
  begin
    if GetSystemDirectoryW(@sysDir[0], 260) > 0 then
    begin
      if (Copy(low, 1, 9) = 'system32\') or (Copy(low, 1, 8) = 'drivers\') or
        (Copy(low, 1, 9) = 'syswow64\') then
        s := WideString(sysDir) + '\' + s;
    end;
  end;
  Result := Trim(s);
end;

{ TScanTouchThread }

constructor TScanTouchThread.Create(AScanForm: TScanForm; AMode: TScanMode;
  const ARoot: WideString; AScanFn: TScanFileFn);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FForm := AScanForm;
  FMode := AMode;
  FRoot := ARoot;
  FCount := 0;
  FScanFn := AScanFn;
end;

procedure TScanTouchThread.PushProgress;
begin
  if FForm = nil then
    Exit;
  if FMode = smFiles then
    FForm.StatusLbl.Caption := 'Touched ' + IntToStr(FCount) + ' files...'
  else
    FForm.StatusLbl.Caption := 'Checked ' + IntToStr(FCount) + ' refs...';
end;

procedure TScanTouchThread.TouchOne(const APath: WideString);
var
  fs: TFileStream;
  buf: array[0..65535] of Byte;
begin
  if Terminated then
    Exit;
  // Open + read head bytes: read-only, share-friendly, never executes.
  // The kernel watcher turns this activity into telemetry for the rules.
  try
    fs := TFileStream.Create(UTF8Encode(APath), fmOpenRead or fmShareDenyNone);
    try
      fs.Read(buf[0], SizeOf(buf));
    finally
      fs.Free;
    end;
  except
    // Locked/system/special files: skip silently.
  end;
end;

function TScanTouchThread.RpcCheckKnown(const APathUtf8: string; out AHash: string): Boolean;
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

procedure TScanTouchThread.PushOne;
var
  Item: TListItem;
  Frm: TScanForm;
begin
  Frm := FForm;
  if (Frm = nil) or (Frm.ResultsView = nil) then
    Exit;
  Item := Frm.ResultsView.Items.Add;
  Item.Caption := '';
  Item.SubItems.Add(Frm.VerdictText(FOneVerdict));
  Item.SubItems.Add(FOnePath + ' :: ' + FOneDetail);
  Item.Data := Pointer(PtrInt(Ord(FOneVerdict)));
  case FOneVerdict of
    svMalicious: InterlockedIncrement(Frm.FMali);
    svKnown: InterlockedIncrement(Frm.FKnown);
    svSafe: InterlockedIncrement(Frm.FSafe);
  else
    InterlockedIncrement(Frm.FUnk);
  end;
  Inc(Frm.FDetections);
  Frm.SummaryLbl.Caption := Format('%d detection(s) shown', [Frm.FDetections]);
end;

procedure TScanTouchThread.ScanOneFile(const APath: WideString);
var
  v: Integer;
  h: string;
  u8: string;
begin
  if Terminated then
    Exit;
  // 1. Touch for the pipeline (driver/service still sees the activity).
  TouchOne(APath);
  if Terminated then
    Exit;
  // 2. Direct static verdict via openedr_static (owlyshield forwarder).
  u8 := UTF8Encode(APath);
  FOnePath := u8;
  FOneVerdict := svUnknown;
  FOneDetail := 'Static: unknown';
  if Assigned(FScanFn) then
  begin
    v := FScanFn(PWideChar(APath), Cardinal(Length(APath)));
    if v = 2 then
    begin
      FOneVerdict := svMalicious;
      FOneDetail := 'Static indicator (openedr_static: ClamAV/YARA/ML/signer)';
    end
    else if v = 1 then
    begin
      FOneVerdict := svSafe;
      FOneDetail := 'Static: clean/trusted';
    end;
  end;
  if (FOneVerdict = svUnknown) and RpcCheckKnown(u8, h) then
  begin
    FOneVerdict := svKnown;
    FOneDetail := 'Known-malware database';
  end;
  // Only list actionable hits immediately; unknowns stay visible via
  // pipeline polling. Always count the touch for progress.
  Inc(FCount);
  if (FCount mod 50) = 0 then
    Synchronize(@PushProgress);
  if FOneVerdict in [svMalicious, svKnown] then
    Synchronize(@PushOne)
  else if not Assigned(FScanFn) then
    Synchronize(@PushOne);
end;

procedure TScanTouchThread.Walk(const ADir: WideString);
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

procedure TScanTouchThread.ScanRegKey(ARoot: HKEY; const AKey: WideString);
var
  reg: TRegistry;
  vals: TStringList;
  i: Integer;
  raw, cleaned: WideString;
  parts: TStringList;
  j: Integer;
  inQuote: Boolean;
  cur, tok: WideString;
  k: Integer;
begin
  // Enumerate value names (TRegistry), read data via Unicode API.
  reg := TRegistry.Create(KEY_READ);
  vals := TStringList.Create;
  try
    reg.RootKey := ARoot;
    if not reg.OpenKeyReadOnly(string(AKey)) then
      Exit;
    reg.GetValueNames(vals);
    for i := 0 to vals.Count - 1 do
    begin
      if Terminated then
        Exit;
      if not ReadRegStringW(ARoot, AKey, WideString(vals[i]), raw) then
        Continue;
      if Trim(WideString(raw)) = '' then
        Continue;
      // Split top-level ',' / ';' (quote-aware).
      parts := TStringList.Create;
      try
        cur := '';
        inQuote := False;
        for k := 1 to Length(raw) + 1 do
        begin
          if k > Length(raw) then
          begin
            tok := Trim(cur);
            if tok <> '' then
              parts.Add(UTF8Encode(tok));
            Break;
          end;
          if raw[k] = '"' then
            inQuote := not inQuote
          else if not inQuote and ((raw[k] = ',') or (raw[k] = ';')) then
          begin
            tok := Trim(cur);
            if tok <> '' then
              parts.Add(UTF8Encode(tok));
            cur := '';
            Continue;
          end;
          cur := cur + raw[k];
        end;
        if parts.Count = 0 then
          parts.Add(UTF8Encode(raw));
        for j := 0 to parts.Count - 1 do
        begin
          if Terminated then
            Exit;
          cleaned := CleanExePath(UTF8Decode(parts[j]));
          if cleaned = '' then
            Continue;
          ScanOneFile(cleaned);
        end;
      finally
        parts.Free;
      end;
    end;
  finally
    vals.Free;
    reg.Free;
  end;
end;

procedure TScanTouchThread.Execute;
var
  up, key: WideString;
  h: HKEY;
  reg: TRegistry;
  subs: TStringList;
  i: Integer;
begin
  FCount := 0;
  if FMode = smFiles then
    Walk(FRoot)
  else
  begin
    // FRoot = e.g. HKLM\path\to\key  or  HKLM\path\to\key\*
    up := WideString(UpperCase(string(FRoot)));
    if Copy(up, 1, 5) = 'HKLM\' then
      h := HKEY_LOCAL_MACHINE
    else if Copy(up, 1, 5) = 'HKCU\' then
      h := HKEY_CURRENT_USER
    else
      Exit;
    key := Copy(FRoot, 6, Length(FRoot));
    if (key <> '') and (key[Length(key)] = '\') and
      (Copy(key, Length(key) - 1, 2) = '\*') then
    begin
      // descend: every direct subkey, all its values
      key := Copy(key, 1, Length(key) - 2);
      reg := TRegistry.Create(KEY_READ);
      subs := TStringList.Create;
      try
        reg.RootKey := h;
        if reg.OpenKeyReadOnly(string(key)) then
        begin
          reg.GetKeyNames(subs);
          reg.CloseKey;
          for i := 0 to subs.Count - 1 do
          begin
            if Terminated then
              Exit;
            ScanRegKey(h, key + WideString('\') + WideString(subs[i]));
          end;
        end;
      finally
        subs.Free;
        reg.Free;
      end;
    end
    else
      ScanRegKey(h, key);
  end;
end;

{ TScanForm }

constructor TScanForm.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  ShowInTaskBar := stAlways;
  FFirstShow := True;
  FLastId := -1;
  FDetections := 0;
end;

procedure TScanForm.CreateParams(var Params: TCreateParams);
begin
  inherited CreateParams(Params);
  Params.ExStyle := Params.ExStyle or WS_EX_APPWINDOW;
  Params.WndParent := 0;
end;

procedure TScanForm.TargetKindChanged(Sender: TObject);
begin
  BrowseBtn.Enabled := RbFiles.Checked;
  if RbReg.Checked then
    PathEdit.TextHint := 'e.g. HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
  else
    PathEdit.TextHint := '';
end;

procedure TScanForm.ResultsDrawItem(Sender: TCustomListView; Item: TListItem;
  State: TCustomDrawState; var DefaultDraw: Boolean);
begin
  if (Item <> nil) and not (cdsSelected in State) then
    if (Item.Index mod 2) = 0 then
      Sender.Canvas.Brush.Color := RGBToColor(240, 244, 247)
    else
      Sender.Canvas.Brush.Color := RGBToColor(250, 251, 252);
end;

procedure TScanForm.BrowseBtnClick(Sender: TObject);
var
  Dir: string;
begin
  if not RbFiles.Checked then
    Exit;
  Dir := Trim(PathEdit.Text);
  if SelectDirectory(Dir, [sdAllowCreate], 0) then
    PathEdit.Text := Dir;
end;

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

procedure TScanForm.StartBtnClick(Sender: TObject);
var
  Root: WideString;
  Mode: TScanMode;
  Up: WideString;
begin
  if FThread <> nil then
    Exit;
  if RbReg.Checked then
  begin
    Mode := smRegistry;
    Root := WideString(Trim(PathEdit.Text));
    if Root = '' then
    begin
      TAlertForm.ShowAlert('Scanner', 'Type a registry key first.',
        asWarning, 3000);
      Exit;
    end;
    Up := WideString(UpperCase(string(Root)));
    if (Copy(Up, 1, 5) <> 'HKLM\') and (Copy(Up, 1, 5) <> 'HKCU\') then
    begin
      TAlertForm.ShowAlert('Scanner',
        'Registry target must start with HKLM\ or HKCU\.', asWarning, 3000);
      Exit;
    end;
  end
  else
  begin
    Mode := smFiles;
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
  end;
  if not RpcLastId(FLastId) then
    FLastId := -1;
  if not LoadEngine then
    TAlertForm.ShowAlert('Scanner',
      'Static engine unavailable (owlyshield_ransom.dll). Direct static verdicts off; pipeline + known-DB only.',
      asWarning, 4000);
  ResultsView.Items.Clear;
  FDetections := 0;
  FMali := 0;
  FKnown := 0;
  FSafe := 0;
  FUnk := 0;
  SummaryLbl.Caption := '';
  ScanProgress.Style := pbstMarquee;
  StartBtn.Enabled := False;
  CancelBtn.Enabled := True;
  StatusLbl.Caption := 'Scanning...';
  FThread := TScanTouchThread.Create(Self, Mode, Root, FScanFn);
  FThread.OnTerminate := @TouchDone;
  FThread.Start;
  PollTimer.Enabled := True;
end;

procedure TScanForm.CancelBtnClick(Sender: TObject);
begin
  if FThread <> nil then
    FThread.Terminate;
  PollTimer.Enabled := False;
  FinishScan('Cancelled.');
end;

procedure TScanForm.TouchDone(Sender: TObject);
begin
  FreeAndNil(FThread);
  PollTimer.Enabled := False;
  FinishScan(Format('Scan done. Static Malicious=%d Known=%d Safe=%d + pipeline results.',
    [FMali, FKnown, FSafe]));
end;

procedure TScanForm.PollTick(Sender: TObject);
begin
  RenderNewDetections;
end;

function RpcLastId(out AId: Int64): Boolean;
var
  Req, Resp: string;
  j, d: TJSONData;
begin
  Result := False;
  AId := -1;
  try
    Req := '{"jsonrpc":"2.0","id":1,"method":"getLastDetectionId","params":{}}';
    if HttpPostJson(GUI_RPC_HOST, GUI_RPC_PORT, Req, Resp) then
    begin
      j := GetJSON(Resp);
      try
        d := j.FindPath('result.lastId');
        if d <> nil then
        begin
          AId := d.AsInteger;
          Result := True;
        end;
      finally
        j.Free;
      end;
    end;
  except
    Result := False;
  end;
end;

procedure TScanForm.RenderNewDetections;
var
  Req, Resp: string;
  j, arr, it, ev: TJSONData;
  d: TJSONData;
  i: Integer;
  t, k, det: string;
  item: TListItem;
begin
  if FLastId < 0 then
    if not RpcLastId(FLastId) then
      Exit;
  try
    Req := '{"jsonrpc":"2.0","id":1,"method":"getDetections","params":{"lastId":' +
      IntToStr(FLastId) + '}}';
    if not HttpPostJson(GUI_RPC_HOST, GUI_RPC_PORT, Req, Resp) then
      Exit;
    j := GetJSON(Resp);
    try
      d := j.FindPath('result.lastId');
      arr := j.FindPath('result.events');
      if arr = nil then
        Exit;
      ResultsView.Items.BeginUpdate;
      try
        for i := 0 to arr.Count - 1 do
        begin
          it := arr.Items[i];
          d := it.FindPath('id');
          if (d <> nil) and (d.AsInteger > FLastId) then
            FLastId := d.AsInteger;
          ev := it.FindPath('event');
          if ev = nil then
            ev := it;
          if not EventSummary(ev, t, k, det) then
            Continue;
          item := ResultsView.Items.Add;
          item.Caption := t;
          item.SubItems.Add(k);
          item.SubItems.Add(det);
          Inc(FDetections);
        end;
      finally
        ResultsView.Items.EndUpdate;
      end;
      d := j.FindPath('result.lastId');
      if (d <> nil) and (d.AsInteger > FLastId) then
        FLastId := d.AsInteger;
    finally
      j.Free;
    end;
  except
    // Transport hiccup: next tick retries.
  end;
  SummaryLbl.Caption := Format('%d detection(s) shown', [FDetections]);
end;

function EventSummary(Ev: TJSONData; out ATime, AKind, ADetail: string): Boolean;
var
  d: TJSONData;
begin
  Result := False;
  ATime := '';
  AKind := '';
  ADetail := '';
  if Ev = nil then
    Exit;
  d := Ev.FindPath('eventType');
  if d = nil then
    d := Ev.FindPath('type');
  if d <> nil then
    AKind := d.AsString;
  d := Ev.FindPath('file.path');
  if d = nil then
    d := Ev.FindPath('quarantineTarget');
  if d = nil then
    d := Ev.FindPath('process.imagePath');
  if d <> nil then
    ADetail := d.AsString;
  d := Ev.FindPath('timestamp');
  if d = nil then
    d := Ev.FindPath('time');
  if d <> nil then
    ATime := d.AsString;
  Result := (AKind <> '') or (ADetail <> '');
end;

procedure TScanForm.FinishScan(const AMsg: string);
begin
  ScanProgress.Style := pbstNormal;
  StartBtn.Enabled := True;
  CancelBtn.Enabled := False;
  StatusLbl.Caption := AMsg;
  RenderNewDetections;
end;

procedure TScanForm.FormShowed(Sender: TObject);
var
  DeskW: WideString;
begin
  SetWindowLong(Handle, GWL_EXSTYLE, GetWindowLong(Handle, GWL_EXSTYLE) or WS_EX_APPWINDOW);
  SetWindowLongPtrW(Handle, GWL_HWNDPARENT, 0);
  if not FFirstShow then
    Exit;
  FFirstShow := False;
  DeskW := WideString(SysUtils.GetEnvironmentVariable('USERPROFILE')) + WideString('\Desktop');
  if (GetFileAttributesW(PWideChar(DeskW)) <> INVALID_FILE_ATTRIBUTES) and
    ((GetFileAttributesW(PWideChar(DeskW)) and FILE_ATTRIBUTE_DIRECTORY) <> 0) then
    PathEdit.Text := UTF8Encode(DeskW);
end;

procedure TScanForm.FormDestroy(Sender: TObject);
begin
  PollTimer.Enabled := False;
  if FThread <> nil then
  begin
    FThread.Terminate;
    FThread.WaitFor;
    FreeAndNil(FThread);
  end;
  UnloadEngine;
end;

end.
