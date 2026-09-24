unit URep;

{ ---------------------------------------------------------------------------
  URep / TRepForm - file reputation screen (NATIVE Windows UI).
  ---------------------------------------------------------------------------
  Display only, no actions, no quarantine, no blocks:
  - Worker walks the picked folder for EVERY file (no extension gate).
  - Batches of 50 go to getFileReputationBulk JSON-RPC (the service computes
    SHA-1 for legacy FLS lookup). Rows show path, SHA-1, cloud verdict and
    the local verdict WITH its cause (never a bare 'Malicious').
  - Rows persist across scans (path-keyed upsert); totals always recount.
  - Pending actions are shown inline with their matching verdict rows;
    Apply carries the pending count in its caption.
  - Selected row: Copy Hash, manual upload to valkyrie.comodo.com and hash
    discussion on forums.comodo.com (browser links, user-driven).
  Unknown verdicts (cloud never saw the file) are normal, not errors.
  The visual layout is defined in urep.lfm.
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, StdCtrls, ComCtrls, Dialogs,
  ExtCtrls, Menus, Windows, LCLType, Clipbrd, LCLIntf, fpjson, jsonparser, UGuiNotify, UAlert;

type
  TRepForm = class; // forward: worker thread references the form

  { TRepWalkThread - collects executable paths, batches RPC verdicts }

  TRepWalkThread = class(TThread)
  private
    FForm: TRepForm;
    FRoot: WideString;
    FBatch: TStringList;
    FCount: Integer;
    FBatchNo: Integer;
    FCurrent: string;
    FPendingJson: string;
    FPendingFailedBatch: TStringList;
    procedure PushProgress;
    procedure Walk(const ADir: WideString);
    procedure Consider(const APath: WideString);
    procedure FlushBatch;
    procedure PushRows;
    procedure PushFailedRows;
  protected
    procedure Execute; override;
  public
    constructor Create(AScanForm: TRepForm; const ARoot: WideString);
    destructor Destroy; override;
  end;

  { TProcRepThread - one-shot getProcessReputation fetch }

  TProcRepThread = class(TThread)
  private
    FForm: TRepForm;
    FJson: string;
    procedure Render;
  protected
    procedure Execute; override;
  public
    constructor Create(AForm: TRepForm);
  end;

  // Exclusion DLL entry: kind 0 = path (mirrors uquar).
  TQExAddFn = function(AKind: Cardinal; AValue: PWideChar; ALen: Cardinal): Integer; cdecl;

  // Per-row action behind the clickable Action cell (Kaspersky-style):
  // 'Q' quarantine, 'I' ignore (exclude), 'S' skip.
  TRowInfo = class
  public
    Item: TListItem;
    Action: Char;
  end;

  { TRepForm }

  TRepForm = class(TForm)
  published
    HeaderPnl: TPanel;
    HeaderAccent: TPanel;
    ToolbarSurface: TPanel;
    StatusSurface: TPanel;
    ResultsArea: TPanel;
    ResultsSurface: TPanel;
    SubtitleLbl: TLabel;
    ResultsSectionLbl: TLabel;
    TitleLbl: TLabel;
    PathEdit: TEdit;
    BrowseBtn: TButton;
    StartBtn: TButton;
    CancelBtn: TButton;
    ProcBtn: TButton;
    CopyBtn: TButton;
    ValkBtn: TButton;
    ForumBtn: TButton;
    ApplyBtn: TButton;
    DetPopup: TPopupMenu;
    DetItem: TMenuItem;
    QuarItem: TMenuItem;
    IgnItem: TMenuItem;
    SelAllItem: TMenuItem;
    QuarAllItem: TMenuItem;
    IgnAllItem: TMenuItem;
    ScanProgress: TProgressBar;
    StatusLbl: TLabel;
    SummaryLbl: TLabel;
    ResultsView: TListView;
    procedure BrowseBtnClick(Sender: TObject);
    procedure StartBtnClick(Sender: TObject);
    procedure CancelBtnClick(Sender: TObject);
    procedure CopyBtnClick(Sender: TObject);
    procedure ValkBtnClick(Sender: TObject);
    procedure ForumBtnClick(Sender: TObject);
    procedure ApplyBtnClick(Sender: TObject);
    procedure QuarItemClick(Sender: TObject);
    procedure IgnItemClick(Sender: TObject);
    procedure SelAllItemClick(Sender: TObject);
    procedure QuarAllItemClick(Sender: TObject);
    procedure IgnAllItemClick(Sender: TObject);
    procedure ProcBtnClick(Sender: TObject);
    procedure DetItemClick(Sender: TObject);
    procedure ResultsDrawItem(Sender: TCustomListView; Item: TListItem;
      State: TCustomDrawState; var DefaultDraw: Boolean);
    procedure FormShowed(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  private
    FThread: TRepWalkThread;
    FProcThread: TProcRepThread;
    FFirstShow: Boolean;
    FMali, FSafe, FUnk, FFail, FLocal: Integer;
    // Rows rendered by the current scan run. Zero at FinishScan means the
    // server returned nothing at all (empty list) — the persistent list is
    // kept and the status says so instead of a bare 'Done.'
    FRowsThisScan: Integer;
    // Seen paths (lowercased) -> TRowInfo. Rows persist across scans:
    // re-scans update cells in place instead of duplicating, and keep the
    // operator's per-row Action choice.
    FSeen: TStringList;
    // Handled paths (quarantined or ignored this session). A new scan is
    // blocked with a warning while unhandled malicious rows remain.
    FActed: TStringList;
    FStagedActions: TStringList;
    FExDll: HMODULE;
    FExAdd: TQExAddFn;
    function UpsertRow(const AKey, ACaption, AHash, ACloudText,
      ALocalText, AFamilyText: string; v, lv: Integer): TListItem;
    procedure RecountSummary;
    procedure RefreshPendingList;
    function QuarantinePending: Integer;
    function ExcludeOne(const ARawPath: string): Boolean;
    function PendingCount: Integer;
    function LoadExEngine: Boolean;
    procedure ProcWalkDone(Sender: TObject);
    procedure WalkDone(Sender: TObject);
    procedure FinishScan(const AMsg: string);
  protected
    procedure CreateParams(var Params: TCreateParams); override;
  public
    constructor Create(AOwner: TComponent); override;
  end;

function EscapeJson(const S: string): string;
function LocalVerdictOf(it: TJSONData): Integer;
function LocalText(v: Integer): string;
function LocalNameOf(it: TJSONData): string;
function LocalCellText(lv: Integer; const AName: string): string;
function FamilyText(lv: Integer; const AName: string): string;
function StripPidPrefix(const S: string): string;
function CloudText(v: Integer): string;

implementation

{$R *.lfm}

const
  VALKYRIE_URL = 'https://valkyrie.comodo.com/';
  FORUMS_URL = 'https://forums.comodo.com/';

// Shortens a path for the status line: '...' + tail.
function ShortPath(const S: string; MaxLen: Integer): string;
begin
  if Length(S) <= MaxLen then
    Result := S
  else
    Result := '...' + Copy(S, Length(S) - MaxLen + 4, MaxInt);
end;

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

{ ---- modern UI helpers -------------------------------------------------- }

function RowColorForVerdict(AVerdict, AIndex: Integer): TColor;
begin
  case AVerdict of
    2: Result := RGBToColor(255, 232, 229); // malicious
    1: Result := RGBToColor(226, 246, 235); // safe
    4: Result := RGBToColor(255, 244, 218); // lookup failed
  else
    if (AIndex mod 2) = 1 then
      Result := RGBToColor(240, 244, 247)     // unknown - zebra stripe
    else
      Result := RGBToColor(250, 251, 252);
  end;
end;

procedure ApplySummaryStyle(Frm: TRepForm);
begin
  if (Frm.FMali > 0) or (Frm.FLocal > 0) then
  begin
    Frm.SummaryLbl.Font.Color := RGBToColor(187, 44, 48);
    Frm.SummaryLbl.Font.Style := [fsBold];
  end
  else if Frm.FUnk > 0 then
  begin
    Frm.SummaryLbl.Font.Color := RGBToColor(95, 111, 121);
    Frm.SummaryLbl.Font.Style := [];
  end
  else
  begin
    Frm.SummaryLbl.Font.Color := RGBToColor(0, 121, 88);
    Frm.SummaryLbl.Font.Style := [fsBold];
  end;
end;

{ TRepWalkThread }

constructor TRepWalkThread.Create(AScanForm: TRepForm; const ARoot: WideString);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FForm := AScanForm;
  FRoot := ARoot;
  FCount := 0;
  FBatch := TStringList.Create;
  FPendingFailedBatch := TStringList.Create;
end;

destructor TRepWalkThread.Destroy;
begin
  FPendingFailedBatch.Free;
  FBatch.Free;
  inherited;
end;

procedure TRepWalkThread.PushFailedRows;
var
  Frm: TRepForm;
  i: Integer;
  fp: string;
begin
  Frm := FForm;
  if (Frm = nil) or (FPendingFailedBatch = nil) then
    Exit;
  Frm.ResultsView.Items.BeginUpdate;
  try
    for i := 0 to FPendingFailedBatch.Count - 1 do
    begin
      fp := FPendingFailedBatch[i];
      Frm.UpsertRow(fp, fp, '', 'Lookup failed', '—', '—', 4, 0);
      Inc(FCount);
      Inc(Frm.FRowsThisScan);
    end;
  finally
    Frm.ResultsView.Items.EndUpdate;
  end;
  Frm.RecountSummary;
end;

procedure TRepWalkThread.PushProgress;
begin
  if FForm = nil then
    Exit;
  FForm.StatusLbl.Caption := 'Checked ' + IntToStr(FCount) + ' files' +
    ' (batch ' + IntToStr(FBatchNo) + ')... ' + ShortPath(FCurrent, 70);
end;

procedure TRepWalkThread.PushRows;
var
  Frm: TRepForm;
  AJson: string;
  j, arr, it, d: TJSONData;
  i, v, lv: Integer;
  fp, fh, nm: string;
begin
  Frm := FForm;
  if Frm = nil then
    Exit;
  AJson := FPendingJson;
  try
    j := GetJSON(AJson);
  except
    Exit;
  end;
  try
    arr := j.FindPath('result.results');
    if (arr = nil) or (arr.JSONType <> jtArray) then
      Exit;
    Frm.ResultsView.Items.BeginUpdate;
    try
      for i := 0 to arr.Count - 1 do
      begin
        it := arr.Items[i];
        fp := '';
        fh := '';
        nm := '';
        v := 3;
        d := it.FindPath('path');
        if d <> nil then
          fp := d.AsString;
        d := it.FindPath('hash');
        if d <> nil then
          fh := d.AsString;
        d := it.FindPath('verdict');
        if d <> nil then
          v := d.AsInteger;
        lv := LocalVerdictOf(it);
        nm := LocalNameOf(it);
        // Persistent rows: same path refreshes its cells (totals recount).
        Frm.UpsertRow(fp, fp, fh, CloudText(v), LocalCellText(lv, nm),
          FamilyText(lv, nm), v, lv);
        Inc(FCount);
        Inc(Frm.FRowsThisScan);
      end;
    finally
      Frm.ResultsView.Items.EndUpdate;
    end;
    Frm.RecountSummary;
  finally
    j.Free;
  end;
end;

procedure TRepWalkThread.FlushBatch;
var
  Req, Resp: string;
  i: Integer;
begin
  if FBatch.Count = 0 then
    Exit;
  Inc(FBatchNo);
  try
    Req := '{"jsonrpc":"2.0","id":1,"method":"getFileReputationBulk","params":{"paths":[';
    for i := 0 to FBatch.Count - 1 do
    begin
      if i > 0 then
        Req := Req + ',';
      Req := Req + '"' + EscapeJson(FBatch[i]) + '"';
    end;
    Req := Req + ']}}';
    if HttpPostJson(GUI_RPC_HOST, GUI_RPC_PORT, Req, Resp) then
    begin
      FPendingJson := Resp;
      Synchronize(@PushRows);
    end
    else
    begin
      FPendingFailedBatch.Assign(FBatch);
      Synchronize(@PushFailedRows);
    end;
  except
    FPendingFailedBatch.Assign(FBatch);
    Synchronize(@PushFailedRows);
  end;
  FBatch.Clear;
end;

procedure TRepWalkThread.Consider(const APath: WideString);
begin
  if Terminated then
    Exit;
  // No extension gate: every file enters the bulk scan (server caps giants).
  FBatch.Add(UTF8Encode(APath));
  FCurrent := UTF8Encode(APath);
  if FBatch.Count >= 50 then
    FlushBatch;
  Inc(FCount);
  if (FCount mod 25) = 0 then
    Synchronize(@PushProgress);
end;

procedure TRepWalkThread.Walk(const ADir: WideString);
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
        Consider(p);
    until not FindNextFileW(h, fd);
  finally
    Windows.FindClose(h);
  end;
end;

procedure TRepWalkThread.Execute;
begin
  FCount := 0;
  FBatchNo := 0;
  FCurrent := '';
  Walk(FRoot);
  FlushBatch;
end;

{ TRepForm }

constructor TRepForm.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  ShowInTaskBar := stAlways;
  FFirstShow := True;
  FSeen := TStringList.Create;
  FSeen.Sorted := True;
  FSeen.Duplicates := dupAccept;
  FSeen.CaseSensitive := False;
  FActed := TStringList.Create;
  FActed.Sorted := True;
  FActed.Duplicates := dupIgnore;
  FActed.CaseSensitive := False;
  FStagedActions := TStringList.Create;
  FStagedActions.Sorted := True;
  FStagedActions.Duplicates := dupIgnore;
  FStagedActions.CaseSensitive := False;
end;

procedure TRepForm.CreateParams(var Params: TCreateParams);
begin
  inherited CreateParams(Params);
  Params.ExStyle := Params.ExStyle or WS_EX_APPWINDOW;
  Params.WndParent := 0;
end;

// Path-keyed upsert: rows persist across scans, re-scans refresh cells.
// Data packs cloud verdict (low byte) + local verdict (high byte).
function TRepForm.UpsertRow(const AKey, ACaption, AHash, ACloudText,
  ALocalText, AFamilyText: string; v, lv: Integer): TListItem;
var
  idx: Integer;
begin
  if FSeen.Find(AKey, idx) then
  begin
    Result := TListItem(FSeen.Objects[idx]);
    Result.Caption := ACaption;
    Result.SubItems[1] := AHash;
    Result.SubItems[2] := ACloudText;
    Result.SubItems[3] := ALocalText;
    Result.SubItems[4] := AFamilyText;
    Result.Data := Pointer(PtrUInt(v or (lv shl 8)));
  end
  else
  begin
    Result := ResultsView.Items.Add;
    Result.Caption := ACaption;
    Result.SubItems.Add('');
    Result.SubItems.Add(AHash);
    Result.SubItems.Add(ACloudText);
    Result.SubItems.Add(ALocalText);
    Result.SubItems.Add(AFamilyText);
    Result.Data := Pointer(PtrUInt(v or (lv shl 8)));
    FSeen.AddObject(AKey, Result);
  end;
end;

// Totals recomputed from all (persistent) rows — never double-counts
// refreshed rows.
procedure TRepForm.RecountSummary;
var
  i, v, lv: Integer;
begin
  FMali := 0;
  FSafe := 0;
  FUnk := 0;
  FFail := 0;
  FLocal := 0;
  for i := 0 to ResultsView.Items.Count - 1 do
  begin
    v := Integer(PtrUInt(ResultsView.Items[i].Data)) and $FF;
    lv := (Integer(PtrUInt(ResultsView.Items[i].Data)) shr 8) and $FF;
    case v of
      2: Inc(FMali);
      1: Inc(FSafe);
      4: Inc(FFail);
    else
      Inc(FUnk);
    end;
    if lv = 2 then
      Inc(FLocal);
  end;
  SummaryLbl.Caption := Format(
    'Malicious: %d   ·   Safe: %d   ·   Unknown: %d   ·   Failed: %d   ·   Local hits: %d',
    [FMali, FSafe, FUnk, FFail, FLocal]);
  ApplySummaryStyle(Self);
  RefreshPendingList;
end;

// Keep the pending action beside its verdict row so the list remains the
// single source of truth for both results and staged actions.
procedure TRepForm.RefreshPendingList;
var
  i, v, lv, n: Integer;
  p, key, actStr: string;
  idx: Integer;
  SeenKeys: TStringList;
begin
  if ResultsView = nil then
    Exit;
  SeenKeys := TStringList.Create;
  SeenKeys.Sorted := True;
  SeenKeys.Duplicates := dupIgnore;
  SeenKeys.CaseSensitive := False;
  try
    ResultsView.Items.BeginUpdate;
    try
      n := 0;
      for i := 0 to ResultsView.Items.Count - 1 do
      begin
        v := Integer(PtrUInt(ResultsView.Items[i].Data)) and $FF;
        lv := (Integer(PtrUInt(ResultsView.Items[i].Data)) shr 8) and $FF;
        p := StripPidPrefix(ResultsView.Items[i].Caption);
        key := LowerCase(p);
        actStr := '';

        if (key <> '') and (SeenKeys.IndexOf(key) < 0) then
        begin
          SeenKeys.Add(key);
          if FActed.Find(key, idx) then
            actStr := 'Applied'
          else if (FStagedActions <> nil) and FStagedActions.Find(key, idx) then
          begin
            if FStagedActions.ValueFromIndex[idx] = 'I' then
              actStr := 'Ignore'
            else
              actStr := 'Quarantine';
            Inc(n);
          end
          else if (v = 2) or (lv = 2) then
          begin
            actStr := 'Quarantine';
            Inc(n);
          end;
        end;

        if ResultsView.Items[i].SubItems.Count > 4 then
          ResultsView.Items[i].SubItems[0] := actStr;
      end;
    finally
      ResultsView.Items.EndUpdate;
    end;
  finally
    SeenKeys.Free;
  end;
  ApplyBtn.Caption := 'Apply Actions (' + IntToStr(n) + ')';
end;

function LocalVerdictOf(it: TJSONData): Integer;
var
  dd: TJSONData;
begin
  Result := 0;
  if it = nil then
    Exit;
  dd := it.FindPath('local');
  if dd <> nil then
    Result := dd.AsInteger;
end;

function LocalText(v: Integer): string;
begin
  case v of
    2: Result := 'Malicious';
    1: Result := 'Safe';
  else
    Result := '—';
  end;
end;

function LocalNameOf(it: TJSONData): string;
var
  dd: TJSONData;
begin
  Result := '';
  if it = nil then
    Exit;
  dd := it.FindPath('local_name');
  if dd <> nil then
    Result := dd.AsString;
end;

// Local cell: verdict plus the cause — never a bare 'Malicious'.
function LocalCellText(lv: Integer; const AName: string): string;
begin
  Result := LocalText(lv);
  if (AName <> '') and ((lv = 1) or (lv = 2)) then
    Result := Result + ': ' + AName;
end;

// Family column: the signature/family behind a local-malicious hit
// (ClamAV sig name, ML label). Cloud-only verdicts carry no name.
function FamilyText(lv: Integer; const AName: string): string;
begin
  if (lv = 2) and (AName <> '') then
    Result := AName
  else
    Result := '—';
end;

function CloudText(v: Integer): string;
begin
  case v of
    2: Result := 'Malicious';
    1: Result := 'Safe';
    4: Result := 'Lookup failed';
  else
    Result := 'Unknown';
  end;
end;

// Packed row Data (cloud in low byte, local in high byte) -> malicious?
function WasMalicious(Data: PtrUInt): Boolean;
var
  v, lv: Integer;
begin
  v := Data and $FF;
  lv := (Data shr 8) and $FF;
  Result := (v = 2) or (lv = 2);
end;

function IsMaliciousNow(v, lv: Integer): Boolean;
begin
  Result := (v = 2) or (lv = 2);
end;

// Proc rows carry "[pid] path": strip the prefix for RPC/DLL calls.
function StripPidPrefix(const S: string): string;
var
  j: Integer;
begin
  Result := Trim(S);
  if (Result <> '') and (Result[1] = '[') then
  begin
    j := Pos('] ', Result);
    if j > 0 then
      Delete(Result, 1, j + 1);
    Result := Trim(Result);
  end;
end;

// Preferred verdict for tinting: decisive local beats cloud.
function PreferredVerdict(Data: PtrUInt): Integer;
var
  lv: Integer;
begin
  lv := (Data shr 8) and $FF;
  if lv <> 0 then
    Result := lv
  else
    Result := Data and $FF;
end;

function RpcQuarantineFile(const APathUtf8: string): Boolean;
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

procedure TRepForm.BrowseBtnClick(Sender: TObject);
var
  Dir: string;
begin
  Dir := Trim(PathEdit.Text);
  if SelectDirectory(Dir, [sdAllowCreate], 0) then
    PathEdit.Text := Dir;
end;

procedure TRepForm.StartBtnClick(Sender: TObject);
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
    StatusLbl.Caption := 'Pick an existing folder first.';
    Exit;
  end;
  if Root[Length(Root)] <> WideChar('\') then
    Root := Root + '\';
  // Rows persist across scans (UpsertRow refreshes); totals recount.
  // A new scan is blocked while unhandled malicious rows remain.
  FRowsThisScan := 0;
  if PendingCount > 0 then
  begin
    StatusLbl.Caption := IntToStr(PendingCount) +
      ' detection(s) still awaiting action. Press Apply Actions first.';
    Exit;
  end;
  SummaryLbl.Caption := '';
  ScanProgress.Style := pbstMarquee;
  StatusLbl.Caption := 'Checking...';
  StartBtn.Enabled := False;
  CancelBtn.Enabled := True;
  FThread := TRepWalkThread.Create(Self, Root);
  FThread.OnTerminate := @WalkDone;
  FThread.Start;
end;

procedure TRepForm.CancelBtnClick(Sender: TObject);
begin
  // Break a batch stuck inside a blocking recv first; the worker thread then
  // observes Terminated between batches and exits.
  CancelHttpPostJson;
  if FThread <> nil then
    FThread.Terminate;
  FinishScan('Cancelled.');
end;

procedure TRepForm.WalkDone(Sender: TObject);
begin
  FreeAndNil(FThread);
  FinishScan('Done.');
end;

procedure TRepForm.ResultsDrawItem(Sender: TCustomListView; Item: TListItem;
  State: TCustomDrawState; var DefaultDraw: Boolean);
begin
  // Row tints from the user's own palette; keep system highlight selected.
  if (Item <> nil) and not (cdsSelected in State) then
    Sender.Canvas.Brush.Color :=
      RowColorForVerdict(PreferredVerdict(PtrUInt(Item.Data)), Item.Index);
end;

procedure TRepForm.FinishScan(const AMsg: string);
begin
  ScanProgress.Style := pbstNormal;
  StartBtn.Enabled := True;
  CancelBtn.Enabled := False;
  if FRowsThisScan = 0 then
    StatusLbl.Caption := AMsg + ' No rows returned; list unchanged.'
  else
    StatusLbl.Caption := AMsg;
  // Recount (not the render-time values): rows persist, and FinishScan must
  // not wipe the Local-hits segment the renderers wrote.
  RecountSummary;
end;

procedure TRepForm.CopyBtnClick(Sender: TObject);
begin
  if (ResultsView.Selected <> nil) and (ResultsView.Selected.SubItems.Count >= 2) then
    Clipboard.AsText := ResultsView.Selected.SubItems[1];
end;

procedure TRepForm.ValkBtnClick(Sender: TObject);
begin
  OpenURL(VALKYRIE_URL);
end;

procedure TRepForm.ForumBtnClick(Sender: TObject);
begin
  OpenURL(FORUMS_URL);
end;

function VerdictMeaning(const AVerdictText: string): string;
begin
  if AVerdictText = 'Malicious' then
    Result := 'Known malicious (cloud verdict 2). Quarantine is recommended.'
  else if AVerdictText = 'Safe' then
    Result := 'Known clean (cloud verdict 1).'
  else if AVerdictText = 'Lookup failed' then
    Result := 'Local lookup error (cloud verdict 4 or transport failure).'
  else
    Result := 'Unknown to the cloud (verdict 3) or file gone (verdict 0). ' +
      'Normal for new or rare files; upload to Valkyrie for analysis.';
end;

procedure TRepForm.ProcBtnClick(Sender: TObject);
var
  T: TProcRepThread;
begin
  if FProcThread <> nil then
    Exit;
  // Rows persist (process rows merge by path); totals recount.
  FRowsThisScan := 0;
  if PendingCount > 0 then
  begin
    StatusLbl.Caption := IntToStr(PendingCount) +
      ' detection(s) still awaiting action. Press Apply Actions first.';
    Exit;
  end;
  SummaryLbl.Caption := '';
  ScanProgress.Style := pbstMarquee;
  StatusLbl.Caption := 'Listing running processes...';
  T := TProcRepThread.Create(Self);
  FProcThread := T;
  T.OnTerminate := @ProcWalkDone;
  T.Start;
end;

{ TProcRepThread }

constructor TProcRepThread.Create(AForm: TRepForm);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FForm := AForm;
end;

procedure TProcRepThread.Execute;
var
  Req, Resp: string;
begin
  FJson := '';
  try
    Req := '{"jsonrpc":"2.0","id":1,"method":"getProcessReputation","params":{}}';
    if HttpPostJson(GUI_RPC_HOST, GUI_RPC_PORT, Req, Resp) then
      FJson := Resp;
  except
    FJson := '';
  end;
end;

procedure TProcRepThread.Render;
var
  Frm: TRepForm;
  j, arr, it, d: TJSONData;
  i, v, pid, lv: Integer;
  fp, fh, nm, raw: string;
begin
  Frm := FForm;
  if (Frm = nil) or (FJson = '') then
    Exit;
  try
    j := GetJSON(FJson);
  except
    Exit;
  end;
  try
    arr := j.FindPath('result.results');
    if (arr = nil) or (arr.JSONType <> jtArray) then
      Exit;
    Frm.ResultsView.Items.BeginUpdate;
    try
      for i := 0 to arr.Count - 1 do
      begin
        it := arr.Items[i];
        fp := '';
        fh := '';
        nm := '';
        raw := '';
        v := 3;
        pid := 0;
        d := it.FindPath('pid');
        if d <> nil then
          pid := d.AsInteger;
        d := it.FindPath('path');
        if d <> nil then
          raw := d.AsString;
        fp := raw;
        if (pid > 0) and (fp <> '') then
          fp := '[' + IntToStr(pid) + '] ' + fp;
        d := it.FindPath('hash');
        if d <> nil then
          fh := d.AsString;
        d := it.FindPath('verdict');
        if d <> nil then
          v := d.AsInteger;
        lv := LocalVerdictOf(it);
        nm := LocalNameOf(it);
        // Keyed by raw path (caption carries the pid prefix).
        Frm.UpsertRow(raw, fp, fh, CloudText(v), LocalCellText(lv, nm),
          FamilyText(lv, nm), v, lv);
        Inc(Frm.FRowsThisScan);
      end;
    finally
      Frm.ResultsView.Items.EndUpdate;
    end;
    Frm.RecountSummary;
  finally
    j.Free;
  end;
end;

procedure TRepForm.ProcWalkDone(Sender: TObject);
var
  T: TProcRepThread;
begin
  T := FProcThread;
  FProcThread := nil;
  if T <> nil then
  begin
    T.Render;
    T.Free;
  end;
  ScanProgress.Style := pbstNormal;
  StatusLbl.Caption := 'Done.';
  SummaryLbl.Caption := Format(
    'Malicious: %d   ·   Safe: %d   ·   Unknown: %d   ·   Failed: %d',
    [FMali, FSafe, FUnk, FFail]);
  ApplySummaryStyle(Self);
end;

// Malicious rows not yet handled (quarantined or ignored this session).
function TRepForm.PendingCount: Integer;
var
  i, v, lv: Integer;
  key: string;
  idx: Integer;
  SeenKeys: TStringList;
begin
  Result := 0;
  SeenKeys := TStringList.Create;
  SeenKeys.Sorted := True;
  SeenKeys.Duplicates := dupIgnore;
  SeenKeys.CaseSensitive := False;
  try
    for i := 0 to ResultsView.Items.Count - 1 do
    begin
      v := Integer(PtrUInt(ResultsView.Items[i].Data)) and $FF;
      lv := (Integer(PtrUInt(ResultsView.Items[i].Data)) shr 8) and $FF;
      if not ((v = 2) or (lv = 2)) then
        Continue;
      key := LowerCase(StripPidPrefix(ResultsView.Items[i].Caption));
      if (key <> '') and not FActed.Find(key, idx) and (SeenKeys.IndexOf(key) < 0) then
      begin
        SeenKeys.Add(key);
        Inc(Result);
      end;
    end;
  finally
    SeenKeys.Free;
  end;
end;

// Quarantines every pending-malicious row (bulk behind ApplyBtnClick and
// the 'Quarantine All' menu item). Returns the quarantined count.
function TRepForm.QuarantinePending: Integer;
var
  i, v, lv: Integer;
  p, key: string;
  idx: Integer;
begin
  Result := 0;
  for i := 0 to ResultsView.Items.Count - 1 do
  begin
    v := Integer(PtrUInt(ResultsView.Items[i].Data)) and $FF;
    lv := (Integer(PtrUInt(ResultsView.Items[i].Data)) shr 8) and $FF;
    if not ((v = 2) or (lv = 2)) then
      Continue;
    p := StripPidPrefix(ResultsView.Items[i].Caption);
    key := LowerCase(p);
    if (key = '') or FActed.Find(key, idx) then
      Continue;
    if RpcQuarantineFile(p) then
    begin
      FActed.Add(key);
      Inc(Result);
    end;
  end;
end;

// Path exclusion via the engine DLL (kind 0 = path). Marks handled.
function TRepForm.ExcludeOne(const ARawPath: string): Boolean;
var
  key: string;
  w: WideString;
begin
  Result := False;
  if ARawPath = '' then
    Exit;
  if not LoadExEngine then
    Exit;
  w := WideString(UTF8Decode(ARawPath));
  if w = '' then
    Exit;
  if FExAdd(0, PWideChar(w), Cardinal(Length(w))) <> 0 then
    Exit;
  key := LowerCase(ARawPath);
  if (key <> '') and (FActed.IndexOf(key) < 0) then
    FActed.Add(key);
  Result := True;
end;

procedure TRepForm.ApplyBtnClick(Sender: TObject);
var
  i, qCount, iCount, errCount: Integer;
  p, key, act: string;
  idx: Integer;
  v, lv: Integer;
  SeenKeys: TStringList;
begin
  qCount := 0;
  iCount := 0;
  errCount := 0;
  SeenKeys := TStringList.Create;
  SeenKeys.Sorted := True;
  SeenKeys.Duplicates := dupIgnore;
  SeenKeys.CaseSensitive := False;
  try
    for i := 0 to ResultsView.Items.Count - 1 do
    begin
      v := Integer(PtrUInt(ResultsView.Items[i].Data)) and $FF;
      lv := (Integer(PtrUInt(ResultsView.Items[i].Data)) shr 8) and $FF;
      p := StripPidPrefix(ResultsView.Items[i].Caption);
      key := LowerCase(p);
      if (key = '') or FActed.Find(key, idx) or (SeenKeys.IndexOf(key) >= 0) then
        Continue;

      act := '';
      if (FStagedActions <> nil) and FStagedActions.Find(key, idx) then
        act := FStagedActions.ValueFromIndex[idx]
      else if (v = 2) or (lv = 2) then
        act := 'Q';

      if act = 'Q' then
      begin
        SeenKeys.Add(key);
        if RpcQuarantineFile(p) then
        begin
          if FActed.IndexOf(key) < 0 then
            FActed.Add(key);
          Inc(qCount);
        end
        else
          Inc(errCount);
      end
      else if act = 'I' then
      begin
        SeenKeys.Add(key);
        if ExcludeOne(p) then
          Inc(iCount)
        else
          Inc(errCount);
      end;
    end;
  finally
    SeenKeys.Free;
  end;

  if FStagedActions <> nil then
    FStagedActions.Clear;
  RefreshPendingList;
  RecountSummary;

  if errCount > 0 then
    StatusLbl.Caption := Format('Applied actions: %d quarantined, %d ignored (%d failed).', [qCount, iCount, errCount])
  else
    StatusLbl.Caption := Format('Applied actions: %d quarantined, %d ignored.', [qCount, iCount]);
end;

procedure TRepForm.QuarItemClick(Sender: TObject);
var
  i, n: Integer;
  p, key: string;
begin
  n := 0;
  for i := 0 to ResultsView.Items.Count - 1 do
  begin
    if not ResultsView.Items[i].Selected then
      Continue;
    p := StripPidPrefix(ResultsView.Items[i].Caption);
    key := LowerCase(p);
    if (key <> '') and (FActed.IndexOf(key) < 0) then
    begin
      FStagedActions.Values[key] := 'Q';
      Inc(n);
    end;
  end;
  StatusLbl.Caption := Format('Staged %d file(s) for Quarantine. Press Apply Actions to execute.', [n]);
  RefreshPendingList;
end;

function TRepForm.LoadExEngine: Boolean;
var
  DllPath: WideString;
begin
  Result := Assigned(FExAdd);
  if Result then
    Exit;
  if FExDll = 0 then
  begin
    DllPath := WideString(ExtractFilePath(ParamStr(0)) + 'owlyshield_ransom.dll');
    FExDll := LoadLibraryW(PWideChar(DllPath));
    if FExDll = 0 then
      FExDll := LoadLibraryW(PWideChar(WideString('owlyshield_ransom.dll')));
  end;
  if FExDll <> 0 then
    FExAdd := TQExAddFn(GetProcAddress(FExDll, 'owlyshield_exclusion_add'));
  Result := Assigned(FExAdd);
end;

procedure TRepForm.IgnItemClick(Sender: TObject);
var
  i, n: Integer;
  p, key: string;
begin
  n := 0;
  for i := 0 to ResultsView.Items.Count - 1 do
  begin
    if not ResultsView.Items[i].Selected then
      Continue;
    p := StripPidPrefix(ResultsView.Items[i].Caption);
    key := LowerCase(p);
    if (key <> '') and (FActed.IndexOf(key) < 0) then
    begin
      FStagedActions.Values[key] := 'I';
      Inc(n);
    end;
  end;
  StatusLbl.Caption := Format('Staged %d path(s) for Ignore. Press Apply Actions to execute.', [n]);
  RefreshPendingList;
end;

procedure TRepForm.SelAllItemClick(Sender: TObject);
begin
  ResultsView.SelectAll;
end;

procedure TRepForm.QuarAllItemClick(Sender: TObject);
var
  i, n, v, lv: Integer;
  p, key: string;
  idx: Integer;
begin
  n := 0;
  for i := 0 to ResultsView.Items.Count - 1 do
  begin
    v := Integer(PtrUInt(ResultsView.Items[i].Data)) and $FF;
    lv := (Integer(PtrUInt(ResultsView.Items[i].Data)) shr 8) and $FF;
    if not ((v = 2) or (lv = 2)) then
      Continue;
    p := StripPidPrefix(ResultsView.Items[i].Caption);
    key := LowerCase(p);
    if (key = '') or FActed.Find(key, idx) then
      Continue;
    FStagedActions.Values[key] := 'Q';
    Inc(n);
  end;
  StatusLbl.Caption := Format('Staged %d file(s) for Quarantine. Press Apply Actions to execute.', [n]);
  RefreshPendingList;
end;

procedure TRepForm.IgnAllItemClick(Sender: TObject);
var
  i, n, v, lv: Integer;
  p, key: string;
  idx: Integer;
begin
  n := 0;
  for i := 0 to ResultsView.Items.Count - 1 do
  begin
    v := Integer(PtrUInt(ResultsView.Items[i].Data)) and $FF;
    lv := (Integer(PtrUInt(ResultsView.Items[i].Data)) shr 8) and $FF;
    if not ((v = 2) or (lv = 2)) then
      Continue;
    p := StripPidPrefix(ResultsView.Items[i].Caption);
    key := LowerCase(p);
    if (key = '') or FActed.Find(key, idx) then
      Continue;
    FStagedActions.Values[key] := 'I';
    Inc(n);
  end;
  StatusLbl.Caption := Format('Staged %d path(s) for Ignore. Press Apply Actions to execute.', [n]);
  RefreshPendingList;
end;

procedure TRepForm.DetItemClick(Sender: TObject);
var
  it: TListItem;
  msg: string;
begin
  it := ResultsView.Selected;
  if it = nil then
    Exit;
  msg := 'File: ' + it.Caption + sLineBreak;
  if it.SubItems.Count >= 2 then
    msg := msg + 'SHA-1 (collision-vulnerable): ' + it.SubItems[1] + sLineBreak;
  if it.SubItems.Count >= 3 then
    msg := msg + 'Cloud: ' + it.SubItems[2] + sLineBreak +
      VerdictMeaning(it.SubItems[2]);
  if it.SubItems.Count >= 4 then
    msg := msg + 'Local: ' + it.SubItems[3] + sLineBreak;
  if it.SubItems.Count >= 5 then
    msg := msg + 'Family: ' + it.SubItems[4] + sLineBreak;
  MessageDlg('Program details', msg, mtInformation, [mbOK], 0);
end;

procedure TRepForm.FormShowed(Sender: TObject);
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

procedure TRepForm.FormDestroy(Sender: TObject);
begin
  if FThread <> nil then
  begin
    FThread.Terminate;
    FThread.WaitFor;
    FreeAndNil(FThread);
  end;
  FreeAndNil(FSeen);
  FreeAndNil(FActed);
  FreeAndNil(FStagedActions);
  FExAdd := nil;
  if FExDll <> 0 then
  begin
    FreeLibrary(FExDll);
    FExDll := 0;
  end;
end;

end.
