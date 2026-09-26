unit UAlert;

{ ---------------------------------------------------------------------------
  UAlert
  ---------------------------------------------------------------------------
  Small toast/notification and interactive HIPS prompt window.
  When TAlertForm.ShowAlert(...) is called, a card appears instantly in the
  bottom-right corner of the screen and closes by itself after a few
  seconds.
  When TAlertForm.ShowInteractivePrompt(...) is called, an interactive
  firewall decision prompt appears. If multiple prompts arrive in succession,
  they are queued in FIFO order without overwriting the currently displayed
  prompt. As each prompt is answered (Allow/Block), the queue automatically
  advances to the next pending prompt until all are resolved.
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
    IsPrompt: Boolean;
    RequestId: string;
    ExePath: string;
    Resolved: Boolean;
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
    BtnAllowAlways: TButton;
    BtnAllowOnce: TButton;
    BtnBlock: TButton;
    BtnQuarantine: TButton;
    MemoPromptLog: TMemo;
    FSeverity: TAlertSeverity;
    FAutoCloseMs: Integer;
    procedure ApplySeverityStyle;
    procedure PositionAtCorner;
    procedure CloseAlert;
    procedure AdvanceOrClose;
    function FindNextUnresolvedPrompt: Integer;
    procedure ShowCurrentAlert;
    procedure UpdateNavigation;
    procedure BtnPrevClick(Sender: TObject);
    procedure BtnNextClick(Sender: TObject);
    procedure BtnAllowAlwaysClick(Sender: TObject);
    procedure BtnAllowOnceClick(Sender: TObject);
    procedure BtnBlockClick(Sender: TObject);
    procedure BtnQuarantineClick(Sender: TObject);
  public
    class procedure ShowAlert(const ATitle, AMsg: string;
      ASeverity: TAlertSeverity = asInfo; AAutoCloseMs: Integer = 6000);
    class procedure ShowInteractivePrompt(const ATitle, AMsg, ARequestId, AExePath: string);
    class procedure LoadHistory;
    class procedure SaveHistory;
    class procedure AppendLastHistoryItem;
  end;

implementation

uses
  UHipPipe;

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
  Item.IsPrompt := False; Item.RequestId := ''; Item.ExePath := ''; Item.Resolved := True;
  
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
      Item.IsPrompt := False; Item.RequestId := ''; Item.ExePath := ''; Item.Resolved := True;
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
begin
  HistFile := 'C:\ProgramData\HydraDragonQuarantine\alerts_history.txt';
  try
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
  except
  end;
end;

class procedure TAlertForm.AppendLastHistoryItem;
var
  F: TextFile;
  HistFile: string;
  n: Integer;
begin
  n := High(FHistory);
  if n < 0 then Exit;
  HistFile := 'C:\ProgramData\HydraDragonQuarantine\alerts_history.txt';
  try
    ForceDirectories(ExtractFilePath(HistFile));
    AssignFile(F, HistFile);
    if FileExists(HistFile) then
    begin
      {$I-} Append(F); {$I+}
    end
    else
    begin
      {$I-} Rewrite(F); {$I+}
    end;
    if IOResult <> 0 then Exit;
    
    WriteLn(F, FHistory[n].Title);
    WriteLn(F, IntToStr(Ord(FHistory[n].Severity)));
    WriteLn(F, FHistory[n].Msg);
    WriteLn(F, '====');
    CloseFile(F);
  except
  end;
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
  Item.IsPrompt := False;
  Item.RequestId := '';
  Item.ExePath := '';
  Item.Resolved := True;

  // Create/reuse the form FIRST: FormCreate must not run after history
  // was already populated (it used to reset it and blank out the toast).
  if FInstance = nil then
    FInstance := TAlertForm.Create(Application);

  // Cap in-memory history to 100 items to avoid memory explosion
  if Length(FHistory) >= 100 then
  begin
    for NewIndex := 0 to Length(FHistory) - 2 do
      FHistory[NewIndex] := FHistory[NewIndex + 1];
    SetLength(FHistory, Length(FHistory) - 1);
    if FCurrentIndex > 0 then
      Dec(FCurrentIndex);
  end;

  NewIndex := Length(FHistory);
  SetLength(FHistory, NewIndex + 1);
  FHistory[NewIndex] := Item;
  AppendLastHistoryItem;

  // If the currently displayed alert is an interactive prompt awaiting user action,
  // do NOT overwrite it with a passive notification! Keep the interactive prompt visible.
  if (FCurrentIndex >= 0) and (FCurrentIndex < Length(FHistory) - 1) and
     (FHistory[FCurrentIndex].IsPrompt) and (not FHistory[FCurrentIndex].Resolved) and (FInstance.Visible) then
  begin
    FInstance.UpdateNavigation;
    Exit;
  end;

  FCurrentIndex := NewIndex;
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
  Color := RGBToColor(248, 250, 251);
  Font.Name := 'Segoe UI';
  Font.Color := RGBToColor(39, 50, 58);
  LblTitle.Caption := '';
  LblTitle.Anchors := [akTop, akLeft, akRight];
  LblTitle.SetBounds(62, 16, ClientWidth - 92, 24);
  LblTitle.Font.Name := 'Segoe UI';
  LblTitle.Font.Height := -16;
  LblMessage.Caption := '';
  LblMessage.Anchors := [akTop, akLeft, akRight, akBottom];
  LblMessage.SetBounds(62, 48, ClientWidth - 82, ClientHeight - 96);
  LblMessage.Font.Name := 'Segoe UI';
  LblMessage.Font.Height := -12;
  BtnClose.Anchors := [akTop, akRight];
  BtnClose.Left := ClientWidth - BtnClose.Width - 16;
  BtnClose.Top := 14;
  BtnClose.Font.Name := 'Segoe UI';
  BtnClose.Font.Style := [fsBold];
  FInstance := Self;

  BtnPrev := TButton.Create(Self);
  BtnPrev.Parent := Self;
  BtnPrev.Caption := '<';
  BtnPrev.Width := 28;
  BtnPrev.Height := 28;
  BtnPrev.Left := 14;
  BtnPrev.Top := ClientHeight - BtnPrev.Height - 10;
  BtnPrev.Font.Name := 'Segoe UI';
  BtnPrev.Anchors := [akLeft, akBottom];
  BtnPrev.OnClick := @BtnPrevClick;

  BtnNext := TButton.Create(Self);
  BtnNext.Parent := Self;
  BtnNext.Caption := '>';
  BtnNext.Width := 28;
  BtnNext.Height := 28;
  BtnNext.Left := BtnPrev.Left + BtnPrev.Width + 6;
  BtnNext.Top := ClientHeight - BtnNext.Height - 10;
  BtnNext.Font.Name := 'Segoe UI';
  BtnNext.Anchors := [akLeft, akBottom];
  BtnNext.OnClick := @BtnNextClick;

  LblCount := TLabel.Create(Self);
  LblCount.Parent := Self;
  LblCount.Caption := '';
  LblCount.Left := BtnNext.Left + BtnNext.Width + 8;
  LblCount.Height := 24;
  LblCount.Top := ClientHeight - LblCount.Height - 10;
  LblCount.Anchors := [akLeft, akBottom];
  LblCount.Layout := tlCenter;
  LblCount.Font.Name := 'Segoe UI';
  LblCount.Font.Color := RGBToColor(95, 111, 121);
  LblCount.Font.Height := -11;
  LblCount.ParentColor := False;
  LblCount.ParentFont := False;

  BtnAllowAlways := TButton.Create(Self);
  BtnAllowAlways.Parent := Self;
  BtnAllowAlways.Caption := 'Allow Always';
  BtnAllowAlways.Width := 104;
  BtnAllowAlways.Height := 34;
  BtnAllowAlways.Left := 10;
  BtnAllowAlways.Top := ClientHeight - BtnAllowAlways.Height - 10;
  BtnAllowAlways.Font.Name := 'Segoe UI';
  BtnAllowAlways.Anchors := [akLeft, akBottom];
  BtnAllowAlways.Visible := False;
  BtnAllowAlways.OnClick := @BtnAllowAlwaysClick;

  BtnAllowOnce := TButton.Create(Self);
  BtnAllowOnce.Parent := Self;
  BtnAllowOnce.Caption := 'Allow Once';
  BtnAllowOnce.Width := 104;
  BtnAllowOnce.Height := 34;
  BtnAllowOnce.Left := BtnAllowAlways.Left + BtnAllowAlways.Width + 6;
  BtnAllowOnce.Top := ClientHeight - BtnAllowOnce.Height - 10;
  BtnAllowOnce.Font.Name := 'Segoe UI';
  BtnAllowOnce.Anchors := [akLeft, akBottom];
  BtnAllowOnce.Visible := False;
  BtnAllowOnce.OnClick := @BtnAllowOnceClick;

  BtnBlock := TButton.Create(Self);
  BtnBlock.Parent := Self;
  BtnBlock.Caption := 'Block';
  BtnBlock.Width := 92;
  BtnBlock.Height := 34;
  BtnBlock.Left := BtnAllowOnce.Left + BtnAllowOnce.Width + 6;
  BtnBlock.Top := ClientHeight - BtnBlock.Height - 10;
  BtnBlock.Font.Name := 'Segoe UI';
  BtnBlock.Anchors := [akLeft, akBottom];
  BtnBlock.Visible := False;
  BtnBlock.OnClick := @BtnBlockClick;

  BtnQuarantine := TButton.Create(Self);
  BtnQuarantine.Parent := Self;
  BtnQuarantine.Caption := 'Quarantine';
  BtnQuarantine.Width := 118;
  BtnQuarantine.Height := 34;
  BtnQuarantine.Left := BtnBlock.Left + BtnBlock.Width + 6;
  BtnQuarantine.Top := ClientHeight - BtnQuarantine.Height - 10;
  BtnQuarantine.Font.Name := 'Segoe UI';
  BtnQuarantine.Anchors := [akLeft, akBottom];
  BtnQuarantine.Visible := False;
  BtnQuarantine.OnClick := @BtnQuarantineClick;

  MemoPromptLog := TMemo.Create(Self);
  MemoPromptLog.Parent := Self;
  MemoPromptLog.Left := 62;
  MemoPromptLog.Top := 50;
  MemoPromptLog.Width := ClientWidth - 76;
  MemoPromptLog.Height := ClientHeight - 50 - 60;
  MemoPromptLog.Anchors := [akTop, akLeft, akRight, akBottom];
  MemoPromptLog.ReadOnly := True;
  MemoPromptLog.ScrollBars := ssAutoBoth;
  MemoPromptLog.WordWrap := True;
  MemoPromptLog.Color := RGBToColor(255, 255, 255);
  MemoPromptLog.Font.Name := 'Consolas';
  MemoPromptLog.Font.Color := RGBToColor(39, 50, 58);
  MemoPromptLog.Font.Height := -11;
  MemoPromptLog.BorderStyle := bsNone;
  MemoPromptLog.Visible := False;
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

  ApplySeverityStyle;
  UpdateNavigation;

  if Item.IsPrompt then
  begin
    Width := 680;
    Height := 470;
    BtnQuarantine.Left := ClientWidth - BtnQuarantine.Width - 14;
    BtnBlock.Left := BtnQuarantine.Left - BtnBlock.Width - 8;
    BtnAllowOnce.Left := BtnBlock.Left - BtnAllowOnce.Width - 8;
    BtnAllowAlways.Left := BtnAllowOnce.Left - BtnAllowAlways.Width - 8;
    BtnAllowAlways.Top := ClientHeight - BtnAllowAlways.Height - 10;
    BtnAllowOnce.Top := BtnAllowAlways.Top;
    BtnBlock.Top := BtnAllowAlways.Top;
    BtnQuarantine.Top := BtnAllowAlways.Top;

    BtnAllowAlways.Enabled := not Item.Resolved;
    BtnAllowOnce.Enabled := not Item.Resolved;
    BtnBlock.Enabled := not Item.Resolved;
    BtnQuarantine.Enabled := not Item.Resolved;

    if Item.Resolved then
      LblTitle.Caption := Item.Title + ' [RESOLVED]'
    else
      LblTitle.Caption := Item.Title;

    LblMessage.Visible := False;
    if MemoPromptLog <> nil then
    begin
      MemoPromptLog.Visible := True;
      MemoPromptLog.Font.Name := 'Consolas';
      MemoPromptLog.Font.Height := -12;
      MemoPromptLog.Text := Item.Msg;
    end;

    BtnAllowAlways.Visible := True;
    BtnAllowOnce.Visible := True;
    BtnBlock.Visible := True;
    BtnQuarantine.Visible := True;

    BtnPrev.Visible := True;
    BtnNext.Visible := True;
    LblCount.Visible := True;
    TimerAutoClose.Enabled := False;
  end
  else
  begin
    Width := 480;
    Height := 220;
    LblTitle.Caption := Item.Title;
    LblMessage.Caption := Item.Msg;
    if MemoPromptLog <> nil then
      MemoPromptLog.Visible := False;
    LblMessage.Visible := True;
    BtnAllowAlways.Visible := False;
    BtnAllowOnce.Visible := False;
    BtnBlock.Visible := False;
    BtnQuarantine.Visible := False;
    BtnPrev.Visible := True;
    BtnNext.Visible := True;
    LblCount.Visible := True;
    TimerAutoClose.Enabled := False;
  end;
  PositionAtCorner;
end;

class procedure TAlertForm.ShowInteractivePrompt(const ATitle, AMsg, ARequestId, AExePath: string);
var
  Item: TAlertItem;
  NewIndex: Integer;
begin
  Item.Title := Trim(ATitle);
  Item.Msg := Trim(AMsg);
  Item.Severity := asCritical;
  Item.AutoCloseMs := 0;
  Item.IsPrompt := True;
  Item.RequestId := ARequestId;
  Item.ExePath := AExePath;
  Item.Resolved := False;

  if FInstance = nil then
    FInstance := TAlertForm.Create(Application);

  // Cap in-memory history to 100 items
  if Length(FHistory) >= 100 then
  begin
    for NewIndex := 0 to Length(FHistory) - 2 do
      FHistory[NewIndex] := FHistory[NewIndex + 1];
    SetLength(FHistory, Length(FHistory) - 1);
    if FCurrentIndex > 0 then
      Dec(FCurrentIndex);
  end;

  NewIndex := Length(FHistory);
  SetLength(FHistory, NewIndex + 1);
  FHistory[NewIndex] := Item;

  // If an interactive prompt is ALREADY visible and waiting for user decision,
  // do NOT wipe it out! Keep the current prompt on screen and update the queue counter.
  if FInstance.Visible and (FCurrentIndex >= 0) and (FCurrentIndex < NewIndex) and
     (FHistory[FCurrentIndex].IsPrompt) and (not FHistory[FCurrentIndex].Resolved) then
  begin
    FInstance.UpdateNavigation;
    Exit;
  end;

  FCurrentIndex := NewIndex;
  FInstance.ShowCurrentAlert;
  FInstance.PositionAtCorner;
  FInstance.AlphaBlend := True;
  FInstance.AlphaBlendValue := 255;
  FInstance.Show;
  FInstance.BringToFront;
  SetWindowPos(FInstance.Handle, HWND_TOPMOST, 0, 0, 0, 0,
    SWP_NOMOVE or SWP_NOSIZE or SWP_SHOWWINDOW);
end;

function TAlertForm.FindNextUnresolvedPrompt: Integer;
var
  i: Integer;
begin
  // Search from current position forward first
  for i := FCurrentIndex + 1 to High(FHistory) do
  begin
    if FHistory[i].IsPrompt and (not FHistory[i].Resolved) then
      Exit(i);
  end;
  // Then search from beginning up to current position
  for i := 0 to FCurrentIndex - 1 do
  begin
    if FHistory[i].IsPrompt and (not FHistory[i].Resolved) then
      Exit(i);
  end;
  Result := -1;
end;

procedure TAlertForm.AdvanceOrClose;
var
  NextIdx: Integer;
begin
  NextIdx := FindNextUnresolvedPrompt;
  if NextIdx >= 0 then
  begin
    FCurrentIndex := NextIdx;
    ShowCurrentAlert;
    PositionAtCorner;
    BringToFront;
    SetWindowPos(Handle, HWND_TOPMOST, 0, 0, 0, 0,
      SWP_NOMOVE or SWP_NOSIZE or SWP_SHOWWINDOW);
  end
  else
    CloseAlert;
end;

procedure TAlertForm.BtnAllowAlwaysClick(Sender: TObject);
begin
  if (FCurrentIndex >= 0) and (FCurrentIndex < Length(FHistory)) and
     (not FHistory[FCurrentIndex].Resolved) then
  begin
    SendHipDecision(FHistory[FCurrentIndex].RequestId, 'allow_always', FHistory[FCurrentIndex].ExePath);
    FHistory[FCurrentIndex].Resolved := True;
    AdvanceOrClose;
  end;
end;

procedure TAlertForm.BtnAllowOnceClick(Sender: TObject);
begin
  if (FCurrentIndex >= 0) and (FCurrentIndex < Length(FHistory)) and
     (not FHistory[FCurrentIndex].Resolved) then
  begin
    SendHipDecision(FHistory[FCurrentIndex].RequestId, 'allow_once', FHistory[FCurrentIndex].ExePath);
    FHistory[FCurrentIndex].Resolved := True;
    AdvanceOrClose;
  end;
end;

procedure TAlertForm.BtnBlockClick(Sender: TObject);
begin
  if (FCurrentIndex >= 0) and (FCurrentIndex < Length(FHistory)) and
     (not FHistory[FCurrentIndex].Resolved) then
  begin
    SendHipDecision(FHistory[FCurrentIndex].RequestId, 'block', FHistory[FCurrentIndex].ExePath);
    FHistory[FCurrentIndex].Resolved := True;
    AdvanceOrClose;
  end;
end;

procedure TAlertForm.BtnQuarantineClick(Sender: TObject);
begin
  if (FCurrentIndex >= 0) and (FCurrentIndex < Length(FHistory)) and
     (not FHistory[FCurrentIndex].Resolved) then
  begin
    SendHipDecision(FHistory[FCurrentIndex].RequestId, 'quarantine', FHistory[FCurrentIndex].ExePath);
    FHistory[FCurrentIndex].Resolved := True;
    AdvanceOrClose;
  end;
end;

procedure TAlertForm.UpdateNavigation;
var
  UnresolvedCount: Integer;
  i: Integer;
begin
  if (BtnPrev = nil) or (BtnNext = nil) then
    Exit;

  BtnPrev.Enabled := FCurrentIndex > 0;
  BtnNext.Enabled :=
    (FCurrentIndex >= 0) and
    (FCurrentIndex < Length(FHistory) - 1);

  if LblCount <> nil then
  begin
    UnresolvedCount := 0;
    for i := 0 to High(FHistory) do
      if FHistory[i].IsPrompt and (not FHistory[i].Resolved) then
        Inc(UnresolvedCount);

    if FCurrentIndex < 0 then
      LblCount.Caption := '0/' + IntToStr(Length(FHistory))
    else if UnresolvedCount > 1 then
      LblCount.Caption := IntToStr(FCurrentIndex + 1) + '/' +
        IntToStr(Length(FHistory)) + ' (' + IntToStr(UnresolvedCount) + ' pending)'
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
  if (FCurrentIndex >= 0) and (FCurrentIndex < Length(FHistory)) and
     (FHistory[FCurrentIndex].IsPrompt) and (not FHistory[FCurrentIndex].Resolved) then
  begin
    SendHipDecision(FHistory[FCurrentIndex].RequestId, 'block', FHistory[FCurrentIndex].ExePath);
    FHistory[FCurrentIndex].Resolved := True;
    AdvanceOrClose;
  end
  else
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
