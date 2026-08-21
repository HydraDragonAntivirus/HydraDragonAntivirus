program edrgui;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  {$IFDEF HASAMIGA}
  athreads,
  {$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, Windows, Unit1, UAlert, USvcControl;

{$R *.res}

const
  cSingleInstanceMutex = 'Global\HydraDragonOpenEDR_EDRGUI_SingleInstance';

var
  hMutex: THandle;

begin
  RequireDerivedFormResource := True;
  Application.Scaled := True;
  {$PUSH}
  {$WARN 5044 OFF} // MainFormOnTaskbar is Windows-only by design
  Application.MainFormOnTaskbar := True;
  {$POP}
  Application.Title := 'HydraDragon EDR Agent';

  // Single-instance guard: silently exit if another edrgui.exe is running.
  hMutex := CreateMutex(nil, False, cSingleInstanceMutex);
  if (hMutex <> 0) and (GetLastError = ERROR_ALREADY_EXISTS) then
    Halt(0);

  Application.Initialize;
  // The main form is only a tray controller; it is never visible.
  Application.ShowMainForm := False;
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.