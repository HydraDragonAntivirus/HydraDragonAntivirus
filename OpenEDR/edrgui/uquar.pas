unit UQuar;

{ ---------------------------------------------------------------------------
  UQuar / TQuarForm - quarantine manager screen (NATIVE Windows UI).
  ---------------------------------------------------------------------------
  Dumb UI shell over Rust FFI (owlyshield_ransom.dll, same folder):
  - owlyshield_quarantine_list    -> items JSON
  - owlyshield_quarantine_restore -> container back to original path
  - owlyshield_quarantine_delete  -> drop container permanently
  - owlyshield_exclusion_list/add/remove (kind 0=path, 1=hash)
  Excluded files are left alone entirely by the engines (no container,
  no delete, no block push). All controls are created in code (no .lfm).
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, StdCtrls, ComCtrls, Dialogs,
  ExtCtrls, Windows, DateUtils, fpjson, jsonparser, UGuiNotify, UAlert;

type
  TQListFn = function(ABuf: PByte; ALen: Cardinal): Cardinal; cdecl;
  TQActionFn = function(APath: PWideChar; ALen: Cardinal): Integer; cdecl;
  TQExAddFn = function(AKind: Cardinal; AValue: PWideChar; ALen: Cardinal): Integer; cdecl;

  { TQuarForm }

  TQuarForm = class(TForm)
  private
    TitleLbl: TLabel;
    ItemsView: TListView;
    RefreshBtn: TButton;
    RestoreBtn: TButton;
    DeleteBtn: TButton;
    ExclLbl: TLabel;
    ExclView: TListView;
    ExclAddBtn: TButton;
    ExclDelBtn: TButton;
    FDll: HMODULE;
    FList: TQListFn;
    FRestore: TQActionFn;
    FDelete: TQActionFn;
    FExList: TQListFn;
    FExAdd: TQExAddFn;
    FExDel: TQExAddFn;
    FFirstShow: Boolean;
    procedure BuildUi;
    function LoadEngine: Boolean;
    procedure UnloadEngine;
    function CallJson(AFn: TQListFn; out AJson: string): Boolean;
    procedure RefreshAll(Sender: TObject);
    procedure RefreshItems;
    procedure RefreshExclusions;
    procedure ItemsDrawItem(Sender: TCustomListView; Item: TListItem;
      State: TCustomDrawState; var DefaultDraw: Boolean);
    procedure ExclDrawItem(Sender: TCustomListView; Item: TListItem;
      State: TCustomDrawState; var DefaultDraw: Boolean);
    procedure RestoreBtnClick(Sender: TObject);
    procedure DeleteBtnClick(Sender: TObject);
    procedure ExclAddBtnClick(Sender: TObject);
    procedure ExclDelBtnClick(Sender: TObject);
    procedure FormShowed(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
  public
    constructor Create(AOwner: TComponent); override;
  end;

implementation

{ ---- modern UI helpers (same language as the verdict screen) ------------- }

function RowColorForQuar(AIndex: Integer): TColor;
begin
  // Contained threats: calm red tint, zebra-striped for readability.
  if (AIndex mod 2) = 1 then
    Result := RGBToColor(253, 231, 230)
  else
    Result := RGBToColor(250, 221, 220);
end;

function RowColorForExcl(AIndex: Integer): TColor;
begin
  if (AIndex mod 2) = 1 then
    Result := RGBToColor(247, 248, 250)
  else
    Result := clWhite;
end;

{ TQuarForm }

constructor TQuarForm.Create(AOwner: TComponent);
begin
  inherited CreateNew(AOwner);
  FFirstShow := True;
  OnShow := @FormShowed;
  BuildUi;
end;

procedure TQuarForm.BuildUi;
const
  M = 12;
  W = 700;
var
  y: Integer;
begin
  Caption := 'HydraDragon Quarantine Manager';
  Width := W;
  Height := 560;
  Position := poScreenCenter;
  Constraints.MinWidth := 560;
  Constraints.MinHeight := 420;

  TitleLbl := TLabel.Create(Self);
  TitleLbl.Parent := Self;
  TitleLbl.SetBounds(M, 10, 500, 22);
  TitleLbl.Caption := 'Quarantined items and exclusions';
  TitleLbl.Font.Style := [fsBold];

  ItemsView := TListView.Create(Self);
  ItemsView.Parent := Self;
  ItemsView.SetBounds(M, 36, W - M * 2, 220);
  ItemsView.Anchors := [akTop, akLeft, akRight];
  ItemsView.ViewStyle := vsReport;
  ItemsView.MultiSelect := True;
  ItemsView.ReadOnly := True;
  ItemsView.RowSelect := True;
  ItemsView.HideSelection := False;
  ItemsView.GridLines := False;
  ItemsView.OnCustomDrawItem := @ItemsDrawItem;
  with ItemsView.Columns.Add do
  begin
    Caption := 'File';
    Width := 250;
  end;
  with ItemsView.Columns.Add do
  begin
    Caption := 'Detection';
    Width := 150;
  end;
  with ItemsView.Columns.Add do
  begin
    Caption := 'Date';
    Width := 120;
  end;
  with ItemsView.Columns.Add do
  begin
    Caption := 'Size';
    Width := 80;
  end;
  with ItemsView.Columns.Add do
  begin
    Caption := 'Container';
    Width := 0;
  end;

  y := 262;
  RefreshBtn := TButton.Create(Self);
  RefreshBtn.Parent := Self;
  RefreshBtn.SetBounds(M, y, 110, 30);
  RefreshBtn.Caption := 'Refresh';
  RefreshBtn.OnClick := @RefreshAll;

  RestoreBtn := TButton.Create(Self);
  RestoreBtn.Parent := Self;
  RestoreBtn.SetBounds(M + 118, y, 110, 30);
  RestoreBtn.Caption := 'Restore';
  RestoreBtn.OnClick := @RestoreBtnClick;

  DeleteBtn := TButton.Create(Self);
  DeleteBtn.Parent := Self;
  DeleteBtn.SetBounds(M + 236, y, 110, 30);
  DeleteBtn.Caption := 'Delete';
  DeleteBtn.OnClick := @DeleteBtnClick;

  ExclLbl := TLabel.Create(Self);
  ExclLbl.Parent := Self;
  ExclLbl.SetBounds(M, y + 40, 500, 20);
  ExclLbl.Caption := 'Exclusions (left alone entirely)';
  ExclLbl.Font.Style := [fsBold];

  ExclView := TListView.Create(Self);
  ExclView.Parent := Self;
  ExclView.SetBounds(M, y + 62, W - M * 2, 130);
  ExclView.Anchors := [akTop, akLeft, akRight, akBottom];
  ExclView.ViewStyle := vsReport;
  ExclView.MultiSelect := True;
  ExclView.ReadOnly := True;
  ExclView.RowSelect := True;
  ExclView.HideSelection := False;
  ExclView.GridLines := False;
  ExclView.OnCustomDrawItem := @ExclDrawItem;
  with ExclView.Columns.Add do
  begin
    Caption := 'Kind';
    Width := 80;
  end;
  with ExclView.Columns.Add do
  begin
    Caption := 'Value';
    Width := 540;
  end;

  ExclAddBtn := TButton.Create(Self);
  ExclAddBtn.Parent := Self;
  ExclAddBtn.SetBounds(M, 500 - 40, 190, 30);
  ExclAddBtn.Anchors := [akLeft, akBottom];
  ExclAddBtn.Caption := 'Exclude selected file';
  ExclAddBtn.OnClick := @ExclAddBtnClick;

  ExclDelBtn := TButton.Create(Self);
  ExclDelBtn.Parent := Self;
  ExclDelBtn.SetBounds(M + 198, 500 - 40, 150, 30);
  ExclDelBtn.Anchors := [akLeft, akBottom];
  ExclDelBtn.Caption := 'Remove exclusion';
  ExclDelBtn.OnClick := @ExclDelBtnClick;
end;

function TQuarForm.LoadEngine: Boolean;
var
  DllPath: WideString;
begin
  Result := Assigned(FList) and Assigned(FRestore) and Assigned(FDelete) and
    Assigned(FExList) and Assigned(FExAdd) and Assigned(FExDel);
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
  begin
    FList := TQListFn(GetProcAddress(FDll, 'owlyshield_quarantine_list'));
    FRestore := TQActionFn(GetProcAddress(FDll, 'owlyshield_quarantine_restore'));
    FDelete := TQActionFn(GetProcAddress(FDll, 'owlyshield_quarantine_delete'));
    FExList := TQListFn(GetProcAddress(FDll, 'owlyshield_exclusion_list'));
    FExAdd := TQExAddFn(GetProcAddress(FDll, 'owlyshield_exclusion_add'));
    FExDel := TQExAddFn(GetProcAddress(FDll, 'owlyshield_exclusion_remove'));
  end;
  Result := Assigned(FList) and Assigned(FRestore) and Assigned(FDelete) and
    Assigned(FExList) and Assigned(FExAdd) and Assigned(FExDel);
end;

procedure TQuarForm.UnloadEngine;
begin
  FList := nil;
  FRestore := nil;
  FDelete := nil;
  FExList := nil;
  FExAdd := nil;
  FExDel := nil;
  if FDll <> 0 then
  begin
    FreeLibrary(FDll);
    FDll := 0;
  end;
end;

function TQuarForm.CallJson(AFn: TQListFn; out AJson: string): Boolean;
var
  need, got: Cardinal;
  buf: PByte;
begin
  Result := False;
  AJson := '';
  if not Assigned(AFn) then
    Exit;
  need := AFn(nil, 0);
  if need = 0 then
  begin
    AJson := '[]';
    Result := True;
    Exit;
  end;
  if need > 32 * 1024 * 1024 then
    Exit;
  GetMem(buf, need + 1);
  try
    got := AFn(buf, need);
    if got = 0 then
      Exit;
    SetString(AJson, PAnsiChar(buf), got);
    Result := True;
  finally
    FreeMem(buf);
  end;
end;

procedure TQuarForm.RefreshItems;
var
  s: string;  j, arr, it, d: TJSONData;
  i: Integer;
  item: TListItem;
begin
  ItemsView.Items.Clear;
  if not CallJson(FList, s) then
    Exit;
  try
    j := GetJSON(s);
  except
    Exit;
  end;
  try
    arr := j;
    if (arr <> nil) and (arr.JSONType <> jtArray) then
      arr := nil;
    if arr = nil then
      Exit;
    ItemsView.Items.BeginUpdate;
    try
      for i := 0 to arr.Count - 1 do
      begin
        it := arr.Items[i];
        item := ItemsView.Items.Add;
        d := it.FindPath('original');
        if d <> nil then
          item.Caption := d.AsString
        else
          item.Caption := '';
        d := it.FindPath('detection');
        if d <> nil then
          item.SubItems.Add(d.AsString)
        else
          item.SubItems.Add('');
        d := it.FindPath('timestamp');
        if (d <> nil) and (d.AsInteger > 0) then
          item.SubItems.Add(DateTimeToStr(UnixToDateTime(d.AsInteger)))
        else
          item.SubItems.Add('');
        d := it.FindPath('size');
        if d <> nil then
          item.SubItems.Add(IntToStr(d.AsInteger) + ' bytes')
        else
          item.SubItems.Add('');
        d := it.FindPath('container');
        if d <> nil then
          item.SubItems.Add(d.AsString)
        else
          item.SubItems.Add('');
      end;
    finally
      ItemsView.Items.EndUpdate;
    end;
  finally
    j.Free;
  end;
end;

procedure TQuarForm.RefreshExclusions;
var
  s: string;
  j, arr, it, d: TJSONData;
  i: Integer;
  item: TListItem;
begin
  ExclView.Items.Clear;
  if not CallJson(FExList, s) then
    Exit;
  try
    j := GetJSON(s);
  except
    Exit;
  end;
  try
    arr := j;
    if (arr <> nil) and (arr.JSONType <> jtArray) then
      arr := nil;
    if arr = nil then
      Exit;
    ExclView.Items.BeginUpdate;
    try
      for i := 0 to arr.Count - 1 do
      begin
        it := arr.Items[i];
        item := ExclView.Items.Add;
        d := it.FindPath('kind');
        if (d <> nil) and (d.AsInteger = 1) then
          item.Caption := 'hash'
        else
          item.Caption := 'path';
        d := it.FindPath('value');
        if d <> nil then
          item.SubItems.Add(d.AsString)
        else
          item.SubItems.Add('');
      end;
    finally
      ExclView.Items.EndUpdate;
    end;
  finally
    j.Free;
  end;
end;

procedure TQuarForm.ItemsDrawItem(Sender: TCustomListView; Item: TListItem;
  State: TCustomDrawState; var DefaultDraw: Boolean);
begin
  // Row tints from the shared palette; keep system highlight selected.
  if (Item <> nil) and not (cdsSelected in State) then
    Sender.Canvas.Brush.Color := RowColorForQuar(Item.Index);
end;

procedure TQuarForm.ExclDrawItem(Sender: TCustomListView; Item: TListItem;
  State: TCustomDrawState; var DefaultDraw: Boolean);
begin
  if (Item <> nil) and not (cdsSelected in State) then
    Sender.Canvas.Brush.Color := RowColorForExcl(Item.Index);
end;

procedure TQuarForm.RefreshAll(Sender: TObject);
begin
  if not LoadEngine then
  begin
    TAlertForm.ShowAlert('Quarantine',
      'Engine unavailable (owlyshield_ransom.dll).', asCritical, 4000);
    Exit;
  end;
  RefreshItems;
  RefreshExclusions;
end;

function QuarAction(AFn: TQActionFn; const AContainer: WideString): Boolean;
begin
  Result := False;
  if not Assigned(AFn) then
    Exit;
  Result := AFn(PWideChar(AContainer), Cardinal(Length(AContainer))) = 0;
end;

procedure TQuarForm.RestoreBtnClick(Sender: TObject);
var
  i, n: Integer;
  c: WideString;
begin
  if not LoadEngine then
    Exit;
  n := 0;
  for i := 0 to ItemsView.Items.Count - 1 do
  begin
    if not ItemsView.Items[i].Selected then
      Continue;
    if ItemsView.Items[i].SubItems.Count < 4 then
      Continue;
    c := WideString(UTF8Decode(ItemsView.Items[i].SubItems[3]));
    if QuarAction(FRestore, c) then
      Inc(n);
  end;
  TAlertForm.ShowAlert('Quarantine', IntToStr(n) + ' item(s) restored.',
    asSuccess, 4000);
  RefreshItems;
end;

procedure TQuarForm.DeleteBtnClick(Sender: TObject);
var
  i, n: Integer;
  c: WideString;
begin
  if not LoadEngine then
    Exit;
  n := 0;
  for i := 0 to ItemsView.Items.Count - 1 do
  begin
    if not ItemsView.Items[i].Selected then
      Continue;
    if ItemsView.Items[i].SubItems.Count < 4 then
      Continue;
    c := WideString(UTF8Decode(ItemsView.Items[i].SubItems[3]));
    if QuarAction(FDelete, c) then
      Inc(n);
  end;
  TAlertForm.ShowAlert('Quarantine', IntToStr(n) + ' item(s) deleted.',
    asSuccess, 4000);
  RefreshItems;
end;

procedure TQuarForm.ExclAddBtnClick(Sender: TObject);
var
  i, n: Integer;
  fp, fh: WideString;
begin
  if not LoadEngine then
    Exit;
  n := 0;
  for i := 0 to ItemsView.Items.Count - 1 do
  begin
    if not ItemsView.Items[i].Selected then
      Continue;
    fp := WideString(UTF8Decode(ItemsView.Items[i].Caption));
    if (fp <> '') and (FExAdd(0, PWideChar(fp), Cardinal(Length(fp))) = 0) then
      Inc(n);
  end;
  TAlertForm.ShowAlert('Exclusions', IntToStr(n) + ' path(s) excluded.',
    asSuccess, 4000);
  RefreshExclusions;
end;

procedure TQuarForm.ExclDelBtnClick(Sender: TObject);
var
  i, n, k: Integer;
  v: WideString;
begin
  if not LoadEngine then
    Exit;
  n := 0;
  for i := 0 to ExclView.Items.Count - 1 do
  begin
    if not ExclView.Items[i].Selected then
      Continue;
    if ExclView.Items[i].SubItems.Count < 1 then
      Continue;
    if ExclView.Items[i].Caption = 'hash' then
      k := 1
    else
      k := 0;
    v := WideString(UTF8Decode(ExclView.Items[i].SubItems[0]));
    if (v <> '') and (FExDel(k, PWideChar(v), Cardinal(Length(v))) = 0) then
      Inc(n);
  end;
  TAlertForm.ShowAlert('Exclusions', IntToStr(n) + ' exclusion(s) removed.',
    asSuccess, 4000);
  RefreshExclusions;
end;

procedure TQuarForm.FormShowed(Sender: TObject);
begin
  if not FFirstShow then
    Exit;
  FFirstShow := False;
  RefreshAll(Sender);
end;

procedure TQuarForm.FormDestroy(Sender: TObject);
begin
  UnloadEngine;
end;

end.
