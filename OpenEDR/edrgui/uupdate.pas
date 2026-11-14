unit UUpdate;

{ ---------------------------------------------------------------------------
  UUpdate  -  automatic updates from the GitHub releases
  ---------------------------------------------------------------------------
  The latest release of HydraDragonAntivirus/HydraDragonAntivirus carries one
  asset, installation.msi. TUpdateCheckThread reads that release from the
  GitHub API, downloads the MSI once per release (cached under
  %LOCALAPPDATA%\HydraDragonAntivirus\Updates\<tag>) and decides whether it is
  newer than what is installed.

  "Newer" is decided by the MSI package code: every build of installation.msi
  gets its own PackageCode, and Windows Installer records the code of the
  package that is installed. The product version is not usable (it is the same
  for every build), and the release tag is nowhere in the installed product.

  InstallUpdate runs msiexec elevated. The product code is fixed, so an update
  over an installed agent is a reinstall of the same product from the new
  package (REINSTALL=ALL REINSTALLMODE=vamus); a plain /i of a newer package
  with the same product code is refused as "already installed".
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TUpdateResult = (urUpToDate, urAvailable, urFailed);

  TUpdateInfo = record
    Tag: string;      // release tag, e.g. viruskov-openedr-6
    MsiPath: string;  // the downloaded installation.msi
    Error: string;    // why the check failed (urFailed)
  end;

  TUpdateDoneEvent = procedure(Sender: TObject; AResult: TUpdateResult;
    const AInfo: TUpdateInfo) of object;

  { One update check on a worker thread. FreeOnTerminate=True; OnDone runs on
    the main thread (Synchronize). }
  TUpdateCheckThread = class(TThread)
  private
    FOnDone: TUpdateDoneEvent;
    FResult: TUpdateResult;
    FInfo: TUpdateInfo;
    procedure DoDone;
    procedure Check;
  protected
    procedure Execute; override;
  public
    constructor Create(AOnDone: TUpdateDoneEvent);
  end;

{ Starts msiexec (elevated, UAC prompt) on AMsiPath. True when it was started. }
function InstallUpdate(const AMsiPath: string): Boolean;

{ Call from the owner's destructor (main thread): a check still running then
  finishes without calling back into the freed owner. }
procedure DetachUpdateCallbacks;

implementation

uses
  Windows, ShellApi, fpjson, jsonparser;

const
  ReleasesLatestUrl =
    'https://api.github.com/repos/HydraDragonAntivirus/HydraDragonAntivirus/releases/latest';
  MsiAssetName = 'installation.msi';
  // installation\src\BuildInfo.wxi strproductid
  AgentProductCode = '{45CC556C-A03B-42FF-A2FE-000000000000}';
  HttpUserAgent = 'HydraDragon-EDR-GUI';

  // WinINet
  INTERNET_OPEN_TYPE_PRECONFIG = 0;
  INTERNET_FLAG_RELOAD = $80000000;
  INTERNET_FLAG_NO_CACHE_WRITE = $04000000;
  INTERNET_FLAG_SECURE = $00800000;
  HTTP_QUERY_STATUS_CODE = 19;
  HTTP_QUERY_FLAG_NUMBER = $20000000;

  // ShellExecuteEx: finish starting the process before returning.
  SEE_MASK_NOASYNC = $00000100;

  // Windows Installer
  INSTALLSTATE_DEFAULT = 5;
  PID_REVNUMBER = 9; // summary information: the package code

type
  HINTERNET = Pointer;
  MSIHANDLE = DWORD;

var
  // Read and written on the main thread only (DoDone runs under Synchronize).
  GCallbacksDetached: Boolean = False;

function InternetOpenW(lpszAgent: PWideChar; dwAccessType: DWORD;
  lpszProxy, lpszProxyBypass: PWideChar; dwFlags: DWORD): HINTERNET;
  stdcall; external 'wininet.dll';
function InternetOpenUrlW(hInternet: HINTERNET; lpszUrl, lpszHeaders: PWideChar;
  dwHeadersLength, dwFlags: DWORD; dwContext: PtrUInt): HINTERNET;
  stdcall; external 'wininet.dll';
function InternetReadFile(hFile: HINTERNET; lpBuffer: Pointer;
  dwNumberOfBytesToRead: DWORD; var lpdwNumberOfBytesRead: DWORD): BOOL;
  stdcall; external 'wininet.dll';
function InternetCloseHandle(hInternet: HINTERNET): BOOL;
  stdcall; external 'wininet.dll';
function HttpQueryInfoW(hRequest: HINTERNET; dwInfoLevel: DWORD; lpBuffer: Pointer;
  var lpdwBufferLength: DWORD; lpdwIndex: PDWORD): BOOL;
  stdcall; external 'wininet.dll';

function MsiQueryProductStateW(szProduct: PWideChar): Integer;
  stdcall; external 'msi.dll';
function MsiGetProductInfoW(szProduct, szAttribute, lpValueBuf: PWideChar;
  var pcchValueBuf: DWORD): UINT; stdcall; external 'msi.dll';
function MsiGetSummaryInformationW(hDatabase: MSIHANDLE; szDatabasePath: PWideChar;
  uiUpdateCount: UINT; var phSummaryInfo: MSIHANDLE): UINT;
  stdcall; external 'msi.dll';
function MsiSummaryInfoGetPropertyW(hSummaryInfo: MSIHANDLE; uiProperty: UINT;
  var puiDataType: UINT; var piValue: Integer; var pftValue: TFileTime;
  szValueBuf: PWideChar; var pcchValueBuf: DWORD): UINT;
  stdcall; external 'msi.dll';
function MsiCloseHandle(hAny: MSIHANDLE): UINT; stdcall; external 'msi.dll';

{ --- HTTP ---------------------------------------------------------------- }

{ GETs AUrl into AOut (a memory or file stream). Raises on failure. }
procedure HttpGet(const AUrl, AHeaders: UnicodeString; AOut: TStream);
var
  hNet, hUrl: HINTERNET;
  Buf: array[0..65535] of Byte;
  Got, Status, Len: DWORD;
begin
  hNet := InternetOpenW(PWideChar(UnicodeString(HttpUserAgent)),
    INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0);
  if hNet = nil then
    raise Exception.CreateFmt('InternetOpen failed (%d)', [GetLastError]);
  try
    hUrl := InternetOpenUrlW(hNet, PWideChar(AUrl),
      PWideChar(AHeaders), Length(AHeaders),
      INTERNET_FLAG_RELOAD or INTERNET_FLAG_NO_CACHE_WRITE or INTERNET_FLAG_SECURE, 0);
    if hUrl = nil then
      raise Exception.CreateFmt('cannot reach %s (%d)', [string(AUrl), GetLastError]);
    try
      Status := 0;
      Len := SizeOf(Status);
      if HttpQueryInfoW(hUrl, HTTP_QUERY_STATUS_CODE or HTTP_QUERY_FLAG_NUMBER,
        @Status, Len, nil) and (Status <> 200) then
        raise Exception.CreateFmt('HTTP %d from %s', [Status, string(AUrl)]);
      repeat
        Got := 0;
        if not InternetReadFile(hUrl, @Buf[0], SizeOf(Buf), Got) then
          raise Exception.CreateFmt('download interrupted (%d)', [GetLastError]);
        if Got > 0 then
          AOut.WriteBuffer(Buf[0], Got);
      until Got = 0;
    finally
      InternetCloseHandle(hUrl);
    end;
  finally
    InternetCloseHandle(hNet);
  end;
end;

{ --- Windows Installer --------------------------------------------------- }

function InstalledPackageCode: string;
var
  Buf: array[0..63] of WideChar;
  Len: DWORD;
begin
  Result := '';
  Len := Length(Buf);
  if MsiGetProductInfoW(PWideChar(UnicodeString(AgentProductCode)),
    PWideChar(UnicodeString('PackageCode')), @Buf[0], Len) = ERROR_SUCCESS then
    Result := string(UnicodeString(PWideChar(@Buf[0])));
end;

function MsiFilePackageCode(const AMsiPath: string): string;
var
  hSum: MSIHANDLE;
  DataType: UINT;
  IntVal: Integer;
  Ft: TFileTime;
  Buf: array[0..63] of WideChar;
  Len: DWORD;
begin
  Result := '';
  hSum := 0;
  if MsiGetSummaryInformationW(0, PWideChar(UnicodeString(AMsiPath)), 0, hSum) <> ERROR_SUCCESS then
    Exit;
  try
    Len := Length(Buf);
    if MsiSummaryInfoGetPropertyW(hSum, PID_REVNUMBER, DataType, IntVal, Ft,
      @Buf[0], Len) = ERROR_SUCCESS then
      Result := string(UnicodeString(PWideChar(@Buf[0])));
  finally
    MsiCloseHandle(hSum);
  end;
end;

function AgentInstalled: Boolean;
begin
  Result := MsiQueryProductStateW(PWideChar(UnicodeString(AgentProductCode))) =
    INSTALLSTATE_DEFAULT;
end;

{ --- cache --------------------------------------------------------------- }

function FileSizeOf(const APath: string): Int64;
var
  Sr: TSearchRec;
begin
  Result := -1;
  if FindFirst(APath, faAnyFile, Sr) = 0 then
  begin
    Result := Sr.Size;
    SysUtils.FindClose(Sr);
  end;
end;

function UpdatesDir: string;
begin
  Result := IncludeTrailingPathDelimiter(SysUtils.GetEnvironmentVariable('LOCALAPPDATA')) +
    'HydraDragonAntivirus\Updates\';
end;

{ Removes the cached MSIs of every release except AKeepTag. }
procedure PruneCache(const AKeepTag: string);
var
  Sr: TSearchRec;
  Dir: string;
begin
  Dir := UpdatesDir;
  if FindFirst(Dir + '*', faDirectory, Sr) = 0 then
  try
    repeat
      if ((Sr.Attr and faDirectory) <> 0) and (Sr.Name <> '.') and (Sr.Name <> '..') and
         not SameText(Sr.Name, AKeepTag) then
      begin
        SysUtils.DeleteFile(Dir + Sr.Name + '\' + MsiAssetName);
        RemoveDir(Dir + Sr.Name);
      end;
    until FindNext(Sr) <> 0;
  finally
    SysUtils.FindClose(Sr);
  end;
end;

{ --- TUpdateCheckThread -------------------------------------------------- }

constructor TUpdateCheckThread.Create(AOnDone: TUpdateDoneEvent);
begin
  FOnDone := AOnDone;
  FreeOnTerminate := True;
  inherited Create(False);
end;

procedure TUpdateCheckThread.Execute;
begin
  FResult := urFailed;
  FInfo := Default(TUpdateInfo);
  try
    Check;
  except
    on E: Exception do
    begin
      FResult := urFailed;
      FInfo.Error := E.Message;
    end;
  end;
  Synchronize(@DoDone);
end;

procedure TUpdateCheckThread.Check;
var
  Json: TStringStream;
  Root: TJSONData;
  Assets: TJSONArray;
  Asset: TJSONObject;
  I: Integer;
  Url, Dir, Part: string;
  Size: Int64;
  F: TFileStream;
  Installed, Offered: string;
begin
  // 1. The latest (non-draft, non-prerelease) release and its installation.msi.
  Json := TStringStream.Create('');
  try
    HttpGet(ReleasesLatestUrl, 'Accept: application/vnd.github+json'#13#10, Json);
    Root := GetJSON(Json.DataString);
  finally
    Json.Free;
  end;
  try
    FInfo.Tag := Root.FindPath('tag_name').AsString;
    Url := '';
    Size := -1;
    Assets := TJSONArray(Root.FindPath('assets'));
    if Assets <> nil then
      for I := 0 to Assets.Count - 1 do
      begin
        Asset := Assets.Objects[I];
        if SameText(Asset.Get('name', ''), MsiAssetName) then
        begin
          Url := Asset.Get('browser_download_url', '');
          Size := Asset.Get('size', Int64(-1));
          Break;
        end;
      end;
  finally
    Root.Free;
  end;
  if (FInfo.Tag = '') or (Url = '') then
    raise Exception.Create('the latest release has no ' + MsiAssetName);

  // 2. Downloaded once per release; a complete earlier download is reused.
  Dir := UpdatesDir + FInfo.Tag + '\';
  FInfo.MsiPath := Dir + MsiAssetName;
  if not (FileExists(FInfo.MsiPath) and ((Size < 0) or (FileSizeOf(FInfo.MsiPath) = Size))) then
  begin
    ForceDirectories(Dir);
    Part := FInfo.MsiPath + '.part';
    F := TFileStream.Create(Part, fmCreate);
    try
      HttpGet(UnicodeString(Url), '', F);
    finally
      F.Free;
    end;
    SysUtils.DeleteFile(FInfo.MsiPath);
    if not RenameFile(Part, FInfo.MsiPath) then
      raise Exception.Create('cannot store ' + FInfo.MsiPath);
  end;
  PruneCache(FInfo.Tag);

  // 3. Newer = a different package than the installed one.
  Offered := MsiFilePackageCode(FInfo.MsiPath);
  if Offered = '' then
    raise Exception.Create('the downloaded ' + MsiAssetName + ' is not a valid MSI');
  Installed := InstalledPackageCode;
  if (Installed <> '') and SameText(Installed, Offered) then
    FResult := urUpToDate
  else
    FResult := urAvailable;
end;

procedure TUpdateCheckThread.DoDone;
begin
  if Assigned(FOnDone) and not GCallbacksDetached then
    FOnDone(Self, FResult, FInfo);
end;

procedure DetachUpdateCallbacks;
begin
  GCallbacksDetached := True;
end;

{ --- install ------------------------------------------------------------- }

function InstallUpdate(const AMsiPath: string): Boolean;
var
  Sei: TShellExecuteInfoW;
  Params: UnicodeString;
begin
  if AgentInstalled then
    Params := '/i "' + UnicodeString(AMsiPath) +
      '" REINSTALL=ALL REINSTALLMODE=vamus /passive /promptrestart'
  else
    Params := '/i "' + UnicodeString(AMsiPath) + '" /passive /promptrestart';
  FillChar(Sei, SizeOf(Sei), 0);
  Sei.cbSize := SizeOf(Sei);
  Sei.fMask := SEE_MASK_NOASYNC;
  Sei.lpVerb := 'runas';
  Sei.lpFile := 'msiexec.exe';
  Sei.lpParameters := PWideChar(Params);
  Sei.nShow := SW_SHOWNORMAL;
  Result := ShellExecuteExW(@Sei);
end;

end.
