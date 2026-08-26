unit UAlert;

{ ---------------------------------------------------------------------------
  UAlert
  ---------------------------------------------------------------------------
  Small toast/notification window, matching the "no direct UI" requirement.
  When TAlertForm.ShowAlert(...) is called, a card appears instantly in the
  bottom-right corner of the screen and closes by itself after a few
  seconds. If several notifications are shown at once, they stack
  vertically.
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, ExtCtrls, StdCtrls, Windows;

type
  TAlertSeverity = (asInfo, asSuccess, asWarning, asCritical);

  TAlertItem = record
    Title: string;
    Msg: string;
    Severity: TAlertSeverity;
    AutoCloseMs: Integer;
  end;

  TAlertForm = class(TForm)
    PanelAccent: TPanel;
    LblIcon: TLabel;
    LblTitle: TLabel;
    LblMessage: TLabel;
    BtnClose: TLabel;
    TimerAutoClose: TTimer;
    TimerFade: TTimer;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure TimerAutoCloseTimer(Sender: TObject);
    procedure TimerFadeTimer(Sender: TObject);
    procedure BtnCloseClick(Sender: TObject);
    procedure FormMouseEnter(Sender: TObject);
    procedure FormMouseLeave(Sender: TObject);
  private
  class var FInstance: TAlertForm;
  class var FHistory: array of TAlertItem;
  class var FCurrentIndex: Integer;
  BtnPrev: TButton;
  BtnNext: TButton;
  LblCount: TLabel;
    FSeverity: TAlertSeverity;
    FAutoCloseMs: Integer;
    procedure ApplySeverityStyle;
    procedure PositionAtCorner;
    procedure CloseAlert;
    procedure ShowCurrentAlert;
    procedure UpdateNavigation;
    procedure BtnPrevClick(Sender: TObject);
    procedure BtnNextClick(Sender: TObject);
  public
    class procedure ShowAlert(const ATitle, AMsg: string;
      ASeverity: TAlertSeverity = asInfo; AAutoCloseMs: Integer = 6000);
    class procedure LoadHistory;
    class procedure SaveHistory;
  end;

implementation

{$R *.lfm}

const
  MARGIN = 14;

var
  Dummy: Integer;

{ TAlertForm }

class procedure TAlertForm.LoadHistory;
var
  F: TextFile;
  Line: string;
  Item: TAlertItem;
  HistFile: string;
begin
  HistFile := 'C:\ProgramData\HydraDragonQuarantine\alerts_history.txt';
  if not FileExists(HistFile) then Exit;
  
  AssignFile(F, HistFile);
  {$I-} Reset(F); {$I+}
  if IOResult <> 0 then Exit;
  
  Item.Title := ''; Item.Msg := ''; Item.Severity := asInfo; Item.AutoCloseMs := 0;
  
  while not EOF(F) do
  begin
    ReadLn(F, Line);
    if Line = '====' then
    begin
      if (Item.Title <> '') or (Item.Msg <> '') then
      begin
        SetLength(FHistory, Length(FHistory) + 1);
        FHistory[Length(FHistory) - 1] := Item;
      end;
      Item.Title := ''; Item.Msg := ''; Item.Severity := asInfo; Item.AutoCloseMs := 0;
    end
    else if Item.Title = '' then
      Item.Title := Line
    else if Item.AutoCloseMs = 0 then // using AutoCloseMs as a flag for severity read
    begin
      Item.Severity := TAlertSeverity(StrToIntDef(Line, 0));
      Item.AutoCloseMs := -1; // marked as read
    end
    else
    begin
      if Item.Msg <> '' then Item.Msg := Item.Msg + LineEnding + Line
      else Item.Msg := Line;
    end;
  end;
  CloseFile(F);
  
  FCurrentIndex := Length(FHistory) - 1;
end;

class procedure TAlertForm.SaveHistory;
var
  F: TextFile;
  i: Integer;
  HistFile: string;
  Lines: TStringList;
begin
  HistFile := 'C:\ProgramData\HydraDragonQuarantine\alerts_history.txt';
  ForceDirectories(ExtractFilePath(HistFile));
  
  AssignFile(F, HistFile);
  {$I-} Rewrite(F); {$I+}
  if IOResult <> 0 then Exit;
  
  for i := 0 to High(FHistory) do
  begin
    WriteLn(F, FHistory[i].Title);
    WriteLn(F, IntToStr(Ord(FHistory[i].Severity)));
    WriteLn(F, FHistory[i].Msg);
    WriteLn(F, '====');
  end;
  CloseFile(F);
end;



class procedure TAlertForm.ShowAlert(const ATitle, AMsg: string;
  ASeverity: TAlertSeverity; AAutoCloseMs: Integer);
var
  Item: TAlertItem;
  NewIndex: Integer;
begin
  Item.Title := Trim(ATitle);
  Item.Msg := Trim(AMsg);
  if (Item.Title = '') and (Item.Msg = '') then
    Exit;
  Item.Severity := ASeverity;
  Item.AutoCloseMs := AAutoCloseMs;

  // Create/reuse the form FIRST: FormCreate must not run after history
  // was already populated (it used to reset it and blank out the toast).
  if FInstance = nil then
    FInstance := TAlertForm.Create(Application);

  NewIndex := Length(FHistory);
  SetLength(FHistory, NewIndex + 1);
  FHistory[NewIndex] := Item;
  FCurrentIndex := NewIndex;
  SaveHistory;

  FInstance.ShowCurrentAlert;
  FInstance.PositionAtCorner;
  FInstance.AlphaBlend := True;
  FInstance.AlphaBlendValue := 0;
  FInstance.Show;
  FInstance.BringToFront;
  SetWindowPos(FInstance.Handle, HWND_TOPMOST, 0, 0, 0, 0,
    SWP_NOMOVE or SWP_NOSIZE or SWP_SHOWWINDOW);
  FInstance.TimerFade.Enabled := True;
end;

procedure TAlertForm.FormCreate(Sender: TObject);
begin
  BorderStyle := bsNone;
  FormStyle := fsStayOnTop;
  Position := poDesigned;
  Color := $00302518;
  LblTitle.Caption := '';
  LblMessage.Caption := '';
  FInstance := Self;

  BtnPrev := TButton.Create(Self);
  BtnPrev.Parent := Self;
  BtnPrev.Caption := '<';
  BtnPrev.Width := 28;
  BtnPrev.Height := 24;
  BtnPrev.Left := 10;
  BtnPrev.Top := ClientHeight - BtnPrev.Height - 8;
  BtnPrev.Anchors := [akLeft, akBottom];
  BtnPrev.OnClick := @BtnPrevClick;

  BtnNext := TButton.Create(Self);
  BtnNext.Parent := Self;
  BtnNext.Caption := '>';
  BtnNext.Width := 28;
  BtnNext.Height := 24;
  BtnNext.Left := BtnPrev.Left + BtnPrev.Width + 4;
  BtnNext.Top := ClientHeight - BtnNext.Height - 8;
  BtnNext.Anchors := [akLeft, akBottom];
  BtnNext.OnClick := @BtnNextClick;

  LblCount := TLabel.Create(Self);
  LblCount.Parent := Self;
  LblCount.Caption := '';
  LblCount.Left := BtnNext.Left + BtnNext.Width + 8;
  LblCount.Height := 24;
  LblCount.Top := ClientHeight - LblCount.Height - 8;
  LblCount.Anchors := [akLeft, akBottom];
  LblCount.Layout := tlCenter;
  LblCount.Font.Color := $00B0A090;
  LblCount.Font.Height := -11;
  LblCount.ParentColor := False;
  LblCount.ParentFont := False;

  // NOTE: do NOT reset FHistory/FCurrentIndex here; class vars are already
  // initialized in the initialization section and ShowAlert may have queued
  // an item before this form was first created.
end;

procedure TAlertForm.FormDestroy(Sender: TObject);
begin
  if FInstance = Self then
    FInstance := nil;
end;

procedure TAlertForm.ApplySeverityStyle;
var
  AccentColor: TColor;
  IconChar: string;
begin
  case FSeverity of
    asSuccess:
      begin
        AccentColor := $0056C271;
        IconChar := 'OK';
      end;
    asWarning:
      begin
        AccentColor := $000AA5F5;
        IconChar := '!';
      end;
    asCritical:
      begin
        AccentColor := $00453AEF;
        IconChar := 'X';
      end;
  else
    begin
      AccentColor := $00F5A13B;
      IconChar := 'i';
    end;
  end;

  PanelAccent.Color := AccentColor;
  LblIcon.Caption := IconChar;
  LblIcon.Font.Color := AccentColor;
end;

procedure TAlertForm.PositionAtCorner;
var
  WorkArea: TRect;
  X, Y: Integer;
begin
  WorkArea := Screen.WorkAreaRect;
  X := WorkArea.Right - Width - MARGIN;
  Y := WorkArea.Bottom - Height - MARGIN;
  SetBounds(X, Y, Width, Height);
end;

procedure TAlertForm.ShowCurrentAlert;
var
  Item: TAlertItem;
begin
  if (FCurrentIndex < 0) or (FCurrentIndex >= Length(FHistory)) then
    Exit;

  Item := FHistory[FCurrentIndex];
  FSeverity := Item.Severity;
  FAutoCloseMs := Item.AutoCloseMs;

  LblTitle.Caption := Item.Title;
  LblMessage.Caption := Item.Msg;
  ApplySeverityStyle;
  UpdateNavigation;

  TimerAutoClose.Enabled := False;
end;

procedure TAlertForm.UpdateNavigation;
begin
  if (BtnPrev = nil) or (BtnNext = nil) then
    Exit;

  BtnPrev.Enabled := FCurrentIndex > 0;
  BtnNext.Enabled :=
    (FCurrentIndex >= 0) and
    (FCurrentIndex < Length(FHistory) - 1);

  if LblCount <> nil then
  begin
    if FCurrentIndex < 0 then
      LblCount.Caption := '0/' + IntToStr(Length(FHistory))
    else
      LblCount.Caption := IntToStr(FCurrentIndex + 1) + '/' +
        IntToStr(Length(FHistory));
  end;
end;

procedure TAlertForm.BtnPrevClick(Sender: TObject);
begin
  if FCurrentIndex <= 0 then
    Exit;

  Dec(FCurrentIndex);
  ShowCurrentAlert;
end;

procedure TAlertForm.BtnNextClick(Sender: TObject);
begin
  if FCurrentIndex < 0 then
    Exit;

  if FCurrentIndex >= Length(FHistory) - 1 then
    Exit;

  Inc(FCurrentIndex);
  ShowCurrentAlert;
end;

procedure TAlertForm.TimerFadeTimer(Sender: TObject);
begin
  if AlphaBlendValue >= 235 then
  begin
    AlphaBlendValue := 255;
    TimerFade.Enabled := False;

    if FAutoCloseMs > 0 then
    begin
      TimerAutoClose.Interval := FAutoCloseMs;
      TimerAutoClose.Enabled := True;
    end;
  end
  else
    AlphaBlendValue := AlphaBlendValue + 25;
end;

procedure TAlertForm.TimerAutoCloseTimer(Sender: TObject);
begin
  TimerAutoClose.Enabled := False;
  CloseAlert;
end;

procedure TAlertForm.BtnCloseClick(Sender: TObject);
begin
  CloseAlert;
end;

procedure TAlertForm.CloseAlert;
begin
  Hide;
end;

procedure TAlertForm.FormMouseEnter(Sender: TObject);
begin
  TimerAutoClose.Enabled := False;
end;

procedure TAlertForm.FormMouseLeave(Sender: TObject);
begin
  if FAutoCloseMs > 0 then
    TimerAutoClose.Enabled := True;
end;

initialization
  TAlertForm.FInstance := nil;
  SetLength(TAlertForm.FHistory, 0);
  TAlertForm.FCurrentIndex := -1;
  TAlertForm.LoadHistory;

finalization
  TAlertForm.FInstance := nil;
  SetLength(TAlertForm.FHistory, 0);

end.
