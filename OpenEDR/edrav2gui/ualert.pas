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
  Classes, SysUtils, Forms, Controls, Graphics, ExtCtrls, StdCtrls;

type
  TAlertSeverity = (asInfo, asSuccess, asWarning, asCritical);

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
    FSeverity: TAlertSeverity;
    FAutoCloseMs: Integer;
    procedure ApplySeverityStyle;
    procedure PositionAtCorner;
    procedure CloseAlert;
  public
    class procedure ShowAlert(const ATitle, AMsg: string;
      ASeverity: TAlertSeverity = asInfo; AAutoCloseMs: Integer = 6000);
  end;

implementation

{$R *.lfm}

const
  MARGIN = 14;

var
  // All toasts currently visible on screen (for stacking)
  ActiveAlerts: TFPList;

{ TAlertForm }

class procedure TAlertForm.ShowAlert(const ATitle, AMsg: string;
  ASeverity: TAlertSeverity; AAutoCloseMs: Integer);
var
  Frm: TAlertForm;
begin
  if ActiveAlerts = nil then
    ActiveAlerts := TFPList.Create;

  Frm := TAlertForm.Create(Application);
  Frm.LblTitle.Caption := ATitle;
  Frm.LblMessage.Caption := AMsg;
  Frm.FSeverity := ASeverity;
  Frm.FAutoCloseMs := AAutoCloseMs;
  Frm.ApplySeverityStyle;

  ActiveAlerts.Add(Frm);
  Frm.PositionAtCorner;

  Frm.AlphaBlend := True;
  Frm.AlphaBlendValue := 0;
  Frm.Show;
  Frm.TimerFade.Enabled := True;
end;

procedure TAlertForm.FormCreate(Sender: TObject);
begin
  BorderStyle := bsNone;
  FormStyle := fsStayOnTop;
  Position := poDesigned;
  Color := $00302518; // dark navy card background
end;

procedure TAlertForm.FormDestroy(Sender: TObject);
begin
  if ActiveAlerts <> nil then
    ActiveAlerts.Remove(Self);
end;

procedure TAlertForm.ApplySeverityStyle;
var
  AccentColor: TColor;
  IconChar: string;
begin
  case FSeverity of
    asSuccess:
      begin
        AccentColor := $0056C271; // green
        IconChar := 'OK';
      end;
    asWarning:
      begin
        AccentColor := $000AA5F5; // amber (BGR)
        IconChar := '!';
      end;
    asCritical:
      begin
        AccentColor := $00453AEF; // red
        IconChar := 'X';
      end;
  else // asInfo
    begin
      AccentColor := $00F5A13B; // blue
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
  X, Y, i: Integer;
  Other: TAlertForm;
begin
  WorkArea := Screen.WorkAreaRect;
  X := WorkArea.Right - Width - MARGIN;
  Y := WorkArea.Bottom - Height - MARGIN;

  // Stack upward so new toasts do not overlap the ones already on screen
  if ActiveAlerts <> nil then
    for i := 0 to ActiveAlerts.Count - 1 do
    begin
      Other := TAlertForm(ActiveAlerts[i]);
      if Other <> Self then
        Y := Y - (Other.Height + 10);
    end;

  SetBounds(X, Y, Width, Height);
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
  Close;
  Release;
end;

procedure TAlertForm.FormMouseEnter(Sender: TObject);
begin
  // On hover, stop auto-close so the user can read it
  TimerAutoClose.Enabled := False;
end;

procedure TAlertForm.FormMouseLeave(Sender: TObject);
begin
  if FAutoCloseMs > 0 then
    TimerAutoClose.Enabled := True;
end;

initialization
  ActiveAlerts := nil;

finalization
  if ActiveAlerts <> nil then
    FreeAndNil(ActiveAlerts);

end.