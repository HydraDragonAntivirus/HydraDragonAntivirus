unit URep;

{ ---------------------------------------------------------------------------
  URep / TRepForm - file reputation screen (NATIVE Windows UI).
  ---------------------------------------------------------------------------
  Display only, no actions, no quarantine, no blocks:
  - Worker walks the picked folder for executables (.exe/.dll/.sys/.msi/
    .scr/.cpl/.ocx/.ps1/.js/.vbs/.bat/.cmd/.msc).
  - Batches of 50 go to getFileReputationBulk JSON-RPC (the service hashes
    and asks the FLS cloud). Rows show path, SHA1 and the cloud verdict.
  - Selected row: Copy Hash, manual upload to valkyrie.comodo.com and hash
    discussion on forums.comodo.com (browser links, user-driven).
  Unknown verdicts (cloud never saw the file) are normal, not errors.
  All controls are created in code (no .lfm): deterministic layout.
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, StdCtrls, ComCtrls, Dialogs,
  ExtCtrls, Menus, Windows, Clipbrd, LCLIntf, fpjson, jsonparser, UGuiNotify, UAlert;

type
  TRepForm = class; // forward: worker thread references the form

  { TRepWalkThread - collects executable paths, batches RPC verdicts }

  TRepWalkThread = class(TThread)
  private
    FForm: TRepForm;
    FRoot: WideString;
    FBatch: TStringList;
    FCount: Integer;
    FPendingJson: string;
    procedure PushProgress;
    procedure Walk(const ADir: WideString);
    procedure Consider(const APath: WideString);
    procedure FlushBatch;
    procedure PushRows;
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

  { TRepForm }

  TRepForm = class(TForm)
  private
    TitleLbl: TLabel;
    PathEdit: TEdit;
    BrowseBtn: TButton;
    StartBtn: TButton;
    CancelBtn: TButton;
    ProcBtn: TButton;
    CopyBtn: TButton;
    ValkBtn: TButton;
    ForumBtn: TButton;
    DetPopup: TPopupMenu;
    DetItem: TMenuItem;
    ScanProgress: TProgressBar;
    StatusLbl: TLabel;
    SummaryLbl: TLabel;
    ResultsView: TListView;
    FThread: TRepWalkThread;
    FProcThread: TProcRepThread;
    FFirstShow: Boolean;
    FMali, FSafe, FUnk, FFail: Integer;
    procedure BuildUi;
    procedure BrowseBtnClick(Sender: TObject);
    procedure StartBtnClick(Sender: TObject);
    procedure CancelBtnClick(Sender: TObject);
    procedure CopyBtnClick(Sender: TObject);
    procedure ValkBtnClick(Sender: TObject);
    procedure ForumBtnClick(Sender: TObject);
    procedure ProcBtnClick(Sender: TObject);
    procedure ProcWalkDone(Sender: TObject);
    procedure DetItemClick(Sender: TObject);
    procedure WalkDone(Sender: TObject);
    procedure FormShowed(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FinishScan(const AMsg: string);
  public
    constructor Create(AOwner: TComponent); override;
  end;

function EscapeJson(const S: string): string;

implementation

const
  VALKYRIE_URL = 'https://valkyrie.comodo.com/';
  FORUMS_URL = 'https://forums.comodo.com/';

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

function IsExecExt(const AName: WideString): Boolean;
var
  e: WideString;
  p, i: Integer;
begin
  Result := False;
  // Extension after the last dot past the last path separator (no
  // LastDelimiter: WideString overload is not portable across FPC RTLs).
  p := 0;
  for i := Length(AName) downto 1 do
    if AName[i] = '.' then
    begin
      p := i;
      Break;
    end
    else if (AName[i] = '\') or (AName[i] = '/') or (AName[i] = ':') then
      Break;
  if p <= 0 then
    Exit;
  e := LowerCase(Copy(AName, p + 1, Length(AName)));
  Result := (e = 'exe') or (e = 'dll') or (e = 'sys') or (e = 'msi') or
    (e = 'scr') or (e = 'cpl') or (e = 'ocx') or (e = 'ps1') or
    (e = 'js') or (e = 'vbs') or (e = 'bat') or (e = 'cmd') or (e = 'msc');
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
end;

destructor TRepWalkThread.Destroy;
begin
  FBatch.Free;
  inherited;
end;

procedure TRepWalkThread.PushProgress;
begin
  if FForm = nil then
    Exit;
  FForm.StatusLbl.Caption := 'Checked ' + IntToStr(FCount) + ' files...';
end;

procedure TRepWalkThread.PushRows;
var
  Frm: TRepForm;
  AJson: string;
  j, arr, it, d: TJSONData;
  i, v: Integer;
  item: TListItem;
  fp, fh: string;
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
        item := Frm.ResultsView.Items.Add;
        item.Caption := fp;
        item.SubItems.Add(fh);
        case v of
          2:
            begin
              item.SubItems.Add('Malicious');
              InterlockedIncrement(Frm.FMali);
            end;
          1:
            begin
              item.SubItems.Add('Safe');
              InterlockedIncrement(Frm.FSafe);
            end;
          4:
            begin
              item.SubItems.Add('Lookup failed');
              InterlockedIncrement(Frm.FFail);
            end;
        else
          begin
            item.SubItems.Add('Unknown');
            InterlockedIncrement(Frm.FUnk);
          end;
        end;
        Inc(FCount);
      end;
    finally
      Frm.ResultsView.Items.EndUpdate;
    end;
    Frm.SummaryLbl.Caption := Format(
      'Malicious: %d, Safe: %d, Unknown: %d, Failed: %d',
      [Frm.FMali, Frm.FSafe, Frm.FUnk, Frm.FFail]);
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
    end;
  except
    // Transport hiccup: batch dropped, walk continues.
  end;
  FBatch.Clear;
end;

procedure TRepWalkThread.Consider(const APath: WideString);
begin
  if Terminated then
    Exit;
  if not IsExecExt(APath) then
    Exit;
  FBatch.Add(UTF8Encode(APath));
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
  Walk(FRoot);
  FlushBatch;
end;

{ TRepForm }

constructor TRepForm.Create(AOwner: TComponent);
begin
  inherited CreateNew(AOwner);
  FFirstShow := True;
  OnShow := @FormShowed;
  BuildUi;
end;

procedure TRepForm.BuildUi;
const
  M = 12;
  W = 700;
var
  y: Integer;
begin
  Caption := 'HydraDragon File Verdict';
  Width := W;
  Height := 554;
  Position := poScreenCenter;
  Constraints.MinWidth := 560;
  Constraints.MinHeight := 400;

  TitleLbl := TLabel.Create(Self);
  TitleLbl.Parent := Self;
  TitleLbl.SetBounds(M, 10, 560, 22);
  TitleLbl.Caption := 'File verdicts (FLS cloud) — display only, no actions taken';
  TitleLbl.Font.Style := [fsBold];

  PathEdit := TEdit.Create(Self);
  PathEdit.Parent := Self;
  PathEdit.SetBounds(M, 40, W - M * 2 - 120, 28);
  PathEdit.Anchors := [akTop, akLeft, akRight];

  BrowseBtn := TButton.Create(Self);
  BrowseBtn.Parent := Self;
  BrowseBtn.SetBounds(W - M - 110, 40, 110, 28);
  BrowseBtn.Anchors := [akTop, akRight];
  BrowseBtn.Caption := 'Browse...';
  BrowseBtn.OnClick := @BrowseBtnClick;

  y := 76;
  StartBtn := TButton.Create(Self);
  StartBtn.Parent := Self;
  StartBtn.SetBounds(M, y, 110, 30);
  StartBtn.Caption := 'Check';
  StartBtn.OnClick := @StartBtnClick;

  CancelBtn := TButton.Create(Self);
  CancelBtn.Parent := Self;
  CancelBtn.SetBounds(M + 118, y, 110, 30);
  CancelBtn.Caption := 'Cancel';
  CancelBtn.Enabled := False;
  CancelBtn.OnClick := @CancelBtnClick;

  CopyBtn := TButton.Create(Self);
  CopyBtn.Parent := Self;
  CopyBtn.SetBounds(M + 236, y, 110, 30);
  CopyBtn.Caption := 'Copy hash';
  CopyBtn.OnClick := @CopyBtnClick;

  ValkBtn := TButton.Create(Self);
  ValkBtn.Parent := Self;
  ValkBtn.SetBounds(M + 354, y, 140, 30);
  ValkBtn.Caption := 'Upload to Valkyrie';
  ValkBtn.OnClick := @ValkBtnClick;

  ForumBtn := TButton.Create(Self);
  ForumBtn.Parent := Self;
  ForumBtn.SetBounds(M + 502, y, 130, 30);
  ForumBtn.Caption := 'Forums';
  ForumBtn.OnClick := @ForumBtnClick;

  ProcBtn := TButton.Create(Self);
  ProcBtn.Parent := Self;
  ProcBtn.SetBounds(M, y + 34, 190, 26);
  ProcBtn.Caption := 'Running processes';
  ProcBtn.OnClick := @ProcBtnClick;

  DetPopup := TPopupMenu.Create(Self);
  DetItem := TMenuItem.Create(DetPopup);
  DetItem.Caption := 'Details...';
  DetItem.OnClick := @DetItemClick;
  DetPopup.Items.Add(DetItem);

  ScanProgress := TProgressBar.Create(Self);
  ScanProgress.Parent := Self;
  ScanProgress.SetBounds(M, y + 72, W - M * 2, 18);
  ScanProgress.Anchors := [akTop, akLeft, akRight];
  ScanProgress.Style := pbstMarquee;

  StatusLbl := TLabel.Create(Self);
  StatusLbl.Parent := Self;
  StatusLbl.SetBounds(M, y + 96, W - M * 2, 20);
  StatusLbl.Anchors := [akTop, akLeft, akRight];
  StatusLbl.Caption := 'Idle.';

  SummaryLbl := TLabel.Create(Self);
  SummaryLbl.Parent := Self;
  SummaryLbl.SetBounds(M, y + 118, W - M * 2, 20);
  SummaryLbl.Anchors := [akTop, akLeft, akRight];
  SummaryLbl.Caption := '';

  ResultsView := TListView.Create(Self);
  ResultsView.Parent := Self;
  ResultsView.SetBounds(M, y + 142, W - M * 2, 554 - (y + 142) - M);
  ResultsView.PopupMenu := DetPopup;
  ResultsView.Anchors := [akTop, akLeft, akRight, akBottom];
  ResultsView.ViewStyle := vsReport;
  ResultsView.MultiSelect := True;
  with ResultsView.Columns.Add do
  begin
    Caption := 'File';
    Width := 300;
  end;
  with ResultsView.Columns.Add do
  begin
    Caption := 'SHA1';
    Width := 260;
  end;
  with ResultsView.Columns.Add do
  begin
    Caption := 'Verdict';
    Width := 100;
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
    TAlertForm.ShowAlert('Verdict', 'Pick an existing folder first.',
      asWarning, 3000);
    Exit;
  end;
  if Root[Length(Root)] <> WideChar('\') then
    Root := Root + '\';
  ResultsView.Items.Clear;
  FMali := 0;
  FSafe := 0;
  FUnk := 0;
  FFail := 0;
  SummaryLbl.Caption := '';
  ScanProgress.Style := pbstMarquee;
  StartBtn.Enabled := False;
  CancelBtn.Enabled := True;
  StatusLbl.Caption := 'Checking...';
  FThread := TRepWalkThread.Create(Self, Root);
  FThread.OnTerminate := @WalkDone;
  FThread.Start;
end;

procedure TRepForm.CancelBtnClick(Sender: TObject);
begin
  if FThread <> nil then
    FThread.Terminate;
  FinishScan('Cancelled.');
end;

procedure TRepForm.WalkDone(Sender: TObject);
begin
  FreeAndNil(FThread);
  FinishScan('Done.');
end;

procedure TRepForm.FinishScan(const AMsg: string);
begin
  ScanProgress.Style := pbstNormal;
  StartBtn.Enabled := True;
  CancelBtn.Enabled := False;
  StatusLbl.Caption := AMsg;
  SummaryLbl.Caption := Format(
    'Malicious: %d, Safe: %d, Unknown: %d, Failed: %d',
    [FMali, FSafe, FUnk, FFail]);
end;

procedure TRepForm.CopyBtnClick(Sender: TObject);
begin
  if (ResultsView.Selected <> nil) and (ResultsView.Selected.SubItems.Count >= 1) then
    Clipboard.AsText := ResultsView.Selected.SubItems[0];
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
  ResultsView.Items.Clear;
  FMali := 0;
  FSafe := 0;
  FUnk := 0;
  FFail := 0;
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
  i, v, pid: Integer;
  item: TListItem;
  fp, fh: string;
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
        v := 3;
        pid := 0;
        d := it.FindPath('pid');
        if d <> nil then
          pid := d.AsInteger;
        d := it.FindPath('path');
        if d <> nil then
          fp := d.AsString;
        if (pid > 0) and (fp <> '') then
          fp := '[' + IntToStr(pid) + '] ' + fp;
        d := it.FindPath('hash');
        if d <> nil then
          fh := d.AsString;
        d := it.FindPath('verdict');
        if d <> nil then
          v := d.AsInteger;
        item := Frm.ResultsView.Items.Add;
        item.Caption := fp;
        item.SubItems.Add(fh);
        case v of
          2:
            begin
              item.SubItems.Add('Malicious');
              InterlockedIncrement(Frm.FMali);
            end;
          1:
            begin
              item.SubItems.Add('Safe');
              InterlockedIncrement(Frm.FSafe);
            end;
          4:
            begin
              item.SubItems.Add('Lookup failed');
              InterlockedIncrement(Frm.FFail);
            end;
        else
          begin
            item.SubItems.Add('Unknown');
            InterlockedIncrement(Frm.FUnk);
          end;
        end;
      end;
    finally
      Frm.ResultsView.Items.EndUpdate;
    end;
    Frm.SummaryLbl.Caption := Format(
      'Malicious: %d, Safe: %d, Unknown: %d, Failed: %d',
      [Frm.FMali, Frm.FSafe, Frm.FUnk, Frm.FFail]);
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
    'Malicious: %d, Safe: %d, Unknown: %d, Failed: %d',
    [FMali, FSafe, FUnk, FFail]);
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
  if it.SubItems.Count >= 1 then
    msg := msg + 'SHA1: ' + it.SubItems[0] + sLineBreak;
  if it.SubItems.Count >= 2 then
    msg := msg + 'Verdict: ' + it.SubItems[1] + sLineBreak +
      VerdictMeaning(it.SubItems[1]);
  MessageDlg('Program details', msg, mtInformation, [mbOK], 0);
end;

procedure TRepForm.FormShowed(Sender: TObject);
var
  DeskW: WideString;
begin
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
end;

end.
