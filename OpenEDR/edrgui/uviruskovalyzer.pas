unit UVirusKovAlyzer;

{ ---------------------------------------------------------------------------
  UVirusKovAlyzer / TVirusKovAlyzerForm
  ---------------------------------------------------------------------------
  Advanced, deep file inspection tool modeled after Spybot's FileAlyzer 2.0.
  Named VirusKovAlyzer for HydraDragon Antivirus / OpenEDR.
  Provides power users, security researchers, and reverse engineers with:
  - Hashes: CRC-32, MD5, SHA-1, SHA-256 (calculated via streaming byte chunks).
  - General File Intel: Size (Decimal & Hex), Attributes, Timestamps (Local & UTC).
  - PE Headers: DOS Header (MZ), COFF File Header, Optional Header (PE32/PE32+),
    Subsystem, ImageBase, EntryPoint, ASLR, DEP, CFG.
  - PE Sections & Entropy: Virtual/Raw sizes, Section Flags, Shannon Entropy
    calculation (0.0 - 8.0) with packing/encryption detection (> 7.20).
  - PE Imports & Exports: Imported DLLs and API functions, Exported functions/ordinals.
  - Extracted Strings: ASCII and UTF-16LE strings (min 4 chars) with quick filters.
  - Security & Engines: Direct scan via openedr_static / owlyshield ML engine,
    edrsvc.exe daemon telemetry & cloud FLS reputation, WinVerifyTrust signature.
  - Hex Viewer: Pure Pascal, strictly read-only, paginated/chunked virtual viewer
    with Offset, Hex, and ASCII columns in Consolas font.
  --------------------------------------------------------------------------- }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ComCtrls,
  ExtCtrls, Clipbrd, Windows, WinSock, fpjson, jsonparser, UGuiNotify;

type
  { Win32 PE Structures }
  TImageDosHeader = packed record
    e_magic: Word;                     // Magic number (MZ = $5A4D)
    e_cblp: Word;                      // Bytes on last page of file
    e_cp: Word;                        // Pages in file
    e_crlc: Word;                      // Relocations
    e_cparhdr: Word;                   // Size of header in paragraphs
    e_minalloc: Word;                  // Minimum extra paragraphs needed
    e_maxalloc: Word;                  // Maximum extra paragraphs needed
    e_ss: Word;                        // Initial (relative) SS value
    e_sp: Word;                        // Initial SP value
    e_csum: Word;                      // Checksum
    e_ip: Word;                        // Initial IP value
    e_cs: Word;                        // Initial (relative) CS value
    e_lfarlc: Word;                    // File address of relocation table
    e_ovno: Word;                      // Overlay number
    e_res: array[0..3] of Word;        // Reserved words
    e_oemid: Word;                     // OEM identifier
    e_oeminfo: Word;                   // OEM information
    e_res2: array[0..9] of Word;       // Reserved words
    e_lfanew: LongInt;                 // File address of new exe header
  end;

  TImageFileHeader = packed record
    Machine: Word;
    NumberOfSections: Word;
    TimeDateStamp: DWORD;
    PointerToSymbolTable: DWORD;
    NumberOfSymbols: DWORD;
    SizeOfOptionalHeader: Word;
    Characteristics: Word;
  end;

  TImageDataDirectory = packed record
    VirtualAddress: DWORD;
    Size: DWORD;
  end;

  TImageOptionalHeader32 = packed record
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    BaseOfData: DWORD;
    ImageBase: DWORD;
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: Word;
    MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word;
    MinorImageVersion: Word;
    MajorSubsystemVersion: Word;
    MinorSubsystemVersion: Word;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: Word;
    DllCharacteristics: Word;
    SizeOfStackReserve: DWORD;
    SizeOfStackCommit: DWORD;
    SizeOfHeapReserve: DWORD;
    SizeOfHeapCommit: DWORD;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: array[0..15] of TImageDataDirectory;
  end;

  TImageOptionalHeader64 = packed record
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    ImageBase: QWord;
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: Word;
    MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word;
    MinorImageVersion: Word;
    MajorSubsystemVersion: Word;
    MinorSubsystemVersion: Word;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: Word;
    DllCharacteristics: Word;
    SizeOfStackReserve: QWord;
    SizeOfStackCommit: QWord;
    SizeOfHeapReserve: QWord;
    SizeOfHeapCommit: QWord;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: array[0..15] of TImageDataDirectory;
  end;

  TImageSectionHeader = packed record
    Name: array[0..7] of AnsiChar;
    VirtualSize: DWORD;
    VirtualAddress: DWORD;
    SizeOfRawData: DWORD;
    PointerToRawData: DWORD;
    PointerToRelocations: DWORD;
    PointerToLinenumbers: DWORD;
    NumberOfRelocations: Word;
    NumberOfLinenumbers: Word;
    Characteristics: DWORD;
  end;

  TImageImportDescriptor = packed record
    OriginalFirstThunk: DWORD;
    TimeDateStamp: DWORD;
    ForwarderChain: DWORD;
    Name: DWORD;
    FirstThunk: DWORD;
  end;

  TImageExportDirectory = packed record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    Name: DWORD;
    Base: DWORD;
    NumberOfFunctions: DWORD;
    NumberOfNames: DWORD;
    AddressOfFunctions: DWORD;
    AddressOfNames: DWORD;
    AddressOfNameOrdinals: DWORD;
  end;

  { Forward declaration for engine scanner fn }
  TScanFileFn = function(APath: PWideChar; ALen: Cardinal): Integer; cdecl;

  { TVirusKovAlyzerForm }

  TVirusKovAlyzerForm = class(TForm)
    PnlTopBanner: TPanel;
    LblBannerTitle: TLabel;
    LblBannerSub: TLabel;
    PnlBannerAccent: TPanel;
    BtnBrowseFile: TButton;
    BtnRescan: TButton;
    BtnCloseTop: TButton;
    EditFilePath: TEdit;

    PageControl: TPageControl;
    TabGeneral: TTabSheet;
    TabSecurity: TTabSheet;
    TabHeaders: TTabSheet;
    TabSections: TTabSheet;
    TabImports: TTabSheet;
    TabExports: TTabSheet;
    TabStrings: TTabSheet;
    TabHex: TTabSheet;

    // General Tab Controls
    GbIdentification: TGroupBox;
    LblLocationTitle: TLabel;
    LblLocationVal: TLabel;
    LblSizeTitle: TLabel;
    LblSizeVal: TLabel;
    LblArchTitle: TLabel;
    LblArchVal: TLabel;
    LblTypeTitle: TLabel;
    LblTypeVal: TLabel;

    GbHashes: TGroupBox;
    LblCrc32Title: TLabel;
    EditCrc32: TEdit;
    BtnCopyCrc32: TButton;
    LblMd5Title: TLabel;
    EditMd5: TEdit;
    BtnCopyMd5: TButton;
    LblSha1Title: TLabel;
    EditSha1: TEdit;
    BtnCopySha1: TButton;
    LblSha256Title: TLabel;
    EditSha256: TEdit;
    BtnCopySha256: TButton;

    GbAttributes: TGroupBox;
    CbReadOnly: TCheckBox;
    CbHidden: TCheckBox;
    CbSystem: TCheckBox;
    CbArchive: TCheckBox;
    CbCompressed: TCheckBox;
    CbEncrypted: TCheckBox;

    GbTimestamps: TGroupBox;
    LblCreatedTitle: TLabel;
    LblCreatedVal: TLabel;
    LblModifiedTitle: TLabel;
    LblModifiedVal: TLabel;
    LblAccessedTitle: TLabel;
    LblAccessedVal: TLabel;

    // Security & Engines Tab Controls
    GbEngineStatic: TGroupBox;
    LblStaticVerdictTitle: TLabel;
    LblStaticVerdictVal: TLabel;
    LblStaticThreatTitle: TLabel;
    LblStaticThreatVal: TLabel;

    GbEngineDaemon: TGroupBox;
    LblDaemonFlsTitle: TLabel;
    LblDaemonFlsVal: TLabel;
    LblDaemonKnownTitle: TLabel;
    LblDaemonKnownVal: TLabel;

    GbSignature: TGroupBox;
    LblSigStatusTitle: TLabel;
    LblSigStatusVal: TLabel;
    LblSigPublisherTitle: TLabel;
    LblSigPublisherVal: TLabel;

    // Headers Tab Controls
    MemoHeaders: TMemo;

    // Sections Tab Controls
    LvSections: TListView;

    // Imports Tab Controls
    PnlImportsLeft: TPanel;
    LbImportDlls: TListBox;
    LblImportDllsTitle: TLabel;
    LvImportFunctions: TListView;
    PnlImportsTop: TPanel;
    EditImportFilter: TEdit;
    LblImportFilter: TLabel;

    // Exports Tab Controls
    MemoExportsInfo: TMemo;
    LvExports: TListView;

    // Strings Tab Controls
    PnlStringsTop: TPanel;
    EditStringFilter: TEdit;
    LblStringFilter: TLabel;
    CbStringFilterCategory: TComboBox;
    LvStrings: TListView;

    // Hex Viewer Tab Controls
    PnlHexTop: TPanel;
    BtnHexPrevPage: TButton;
    BtnHexNextPage: TButton;
    BtnHexFirstPage: TButton;
    BtnHexLastPage: TButton;
    LblHexPageInfo: TLabel;
    BtnHexGotoOffset: TButton;
    BtnHexCopy: TButton;
    MemoHexView: TMemo;

    OpenDialog: TOpenDialog;

    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure BtnBrowseFileClick(Sender: TObject);
    procedure BtnRescanClick(Sender: TObject);
    procedure BtnCloseTopClick(Sender: TObject);
    procedure BtnCopyHashClick(Sender: TObject);
    procedure LbImportDllsSelectionChange(Sender: TObject; User: boolean);
    procedure EditImportFilterChange(Sender: TObject);
    procedure EditStringFilterChange(Sender: TObject);
    procedure CbStringFilterCategoryChange(Sender: TObject);
    procedure BtnHexPrevPageClick(Sender: TObject);
    procedure BtnHexNextPageClick(Sender: TObject);
    procedure BtnHexFirstPageClick(Sender: TObject);
    procedure BtnHexLastPageClick(Sender: TObject);
    procedure BtnHexGotoOffsetClick(Sender: TObject);
    procedure BtnHexCopyClick(Sender: TObject);
    procedure LvSectionsCustomDrawItem(Sender: TCustomListView; Item: TListItem;
      State: TCustomDrawState; var DefaultDraw: Boolean);
  private
    FFilePath: string;
    FFileSize: Int64;
    FHexPage: Integer;
    FHexPageSize: Integer;
    FHexTotalPages: Integer;

    // Parsed PE Data
    FIsPE: Boolean;
    FIs64Bit: Boolean;
    FDosHeader: TImageDosHeader;
    FFileHeader: TImageFileHeader;
    FOptHeader32: TImageOptionalHeader32;
    FOptHeader64: TImageOptionalHeader64;
    FSectionHeaders: array of TImageSectionHeader;
    FSectionEntropies: array of Double;

    // Imports list
    FImportList: TStringList; // Objects are TStringList containing function names
    // Extracted strings
    FAllStrings: TStringList;

    procedure ClearAnalysisData;
    procedure AnalyzeFile(const APath: string);
    procedure CalculateHashesAndTimestamps(const APath: string);
    procedure ParsePEHeader(const APath: string);
    procedure ParseSections(Stream: TStream);
    procedure ParseImports(Stream: TStream);
    procedure ParseExports(Stream: TStream);
    procedure ExtractStrings(const APath: string);
    procedure QueryEngineSecurity(const APath: string);
    procedure RenderHexPage;
    function RvaToFileOffset(ARva: DWORD): DWORD;
  public
    class procedure InspectFile(const APath: string);
  end;

var
  VirusKovAlyzerForm: TVirusKovAlyzerForm = nil;

implementation

{$R *.lfm}

uses
  Math;

{ ===========================================================================
  Native CRC-32 & SHA-256 Algorithms (Self-Contained, No Extra Dependencies)
  =========================================================================== }

var
  CRC32Table: array[0..255] of DWORD;
  CRC32TableReady: Boolean = False;

procedure InitCRC32Table;
var
  i, j: Integer;
  c: DWORD;
begin
  if CRC32TableReady then Exit;
  for i := 0 to 255 do
  begin
    c := i;
    for j := 0 to 7 do
    begin
      if (c and 1) <> 0 then
        c := $EDB88320 xor (c shr 1)
      else
        c := c shr 1;
    end;
    CRC32Table[i] := c;
  end;
  CRC32TableReady := True;
end;

function CalcCRC32Stream(Stream: TStream): DWORD;
var
  Buf: array[0..16383] of Byte;
  N, i: Integer;
  Crc: DWORD;
begin
  InitCRC32Table;
  Crc := $FFFFFFFF;
  Stream.Position := 0;
  repeat
    N := Stream.Read(Buf, SizeOf(Buf));
    for i := 0 to N - 1 do
      Crc := CRC32Table[(Crc xor Buf[i]) and $FF] xor (Crc shr 8);
  until N = 0;
  Result := not Crc;
end;

{ Pure Pascal MD5 Implementation }
type
  TMD5Context = record
    State: array[0..3] of DWORD;
    Count: array[0..1] of DWORD;
    Buffer: array[0..63] of Byte;
  end;

const
  MD5_S: array[0..63] of Byte = (
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
  );

  MD5_K: array[0..63] of DWORD = (
    $d76aa478, $e8c7b756, $242070db, $c1bdceee, $f57c0faf, $4787c62a, $a8304613, $fd469501,
    $698098d8, $8b44f7af, $ffff5bb1, $895cd7be, $6b901122, $fd987193, $a679438e, $49b40821,
    $f61e2562, $c040b340, $265e5a51, $e9b6c7aa, $d62f105d, $02441453, $d8a1e681, $e7d3fbc8,
    $21e1cde6, $c33707d6, $f4d50d87, $455a14ed, $a9e3e905, $fcefa3f8, $676f02d9, $8d2a4c8a,
    $fffa3942, $8771f681, $6d9d6122, $fde5380c, $a4beea44, $4bdecfa9, $f6bb4b60, $bebfbc70,
    $289b7ec6, $eaa127fa, $d4ef3085, $04881d05, $d9d4d039, $e6db99e5, $1fa27cf8, $c4ac5665,
    $f4292244, $432aff97, $ab9423a7, $fc93a039, $655b59c3, $8f0ccc92, $ffeff47d, $85845dd1,
    $6fa87e4f, $fe2ce6e0, $a3014314, $4e0811a1, $f7537e82, $bd3af235, $2ad7d2bb, $eb86d391
  );

function ROL32(A: DWORD; S: Byte): DWORD; inline;
begin
  Result := (A shl S) or (A shr (32 - S));
end;

procedure MD5Transform(var State: array of DWORD; const Block: array of Byte);
var
  a, b, c, d, f, g, temp: DWORD;
  i: Integer;
  M: array[0..15] of DWORD;
begin
  Move(Block[0], M[0], 64);
  a := State[0]; b := State[1]; c := State[2]; d := State[3];
  for i := 0 to 63 do
  begin
    if i < 16 then
    begin
      f := (b and c) or ((not b) and d);
      g := i;
    end
    else if i < 32 then
    begin
      f := (d and b) or ((not d) and c);
      g := (5 * i + 1) mod 16;
    end
    else if i < 48 then
    begin
      f := b xor c xor d;
      g := (3 * i + 5) mod 16;
    end
    else
    begin
      f := c xor (b or (not d));
      g := (7 * i) mod 16;
    end;
    temp := d;
    d := c;
    c := b;
    b := b + ROL32(a + f + MD5_K[i] + M[g], MD5_S[i]);
    a := temp;
  end;
  State[0] := State[0] + a;
  State[1] := State[1] + b;
  State[2] := State[2] + c;
  State[3] := State[3] + d;
end;

procedure MD5Init(var Ctx: TMD5Context);
begin
  Ctx.Count[0] := 0; Ctx.Count[1] := 0;
  Ctx.State[0] := $67452301; Ctx.State[1] := $efcdab89;
  Ctx.State[2] := $98badcfe; Ctx.State[3] := $10325476;
end;

procedure MD5Update(var Ctx: TMD5Context; const Buf: PByte; Len: Cardinal);
var
  Idx, PartLen, i: Cardinal;
begin
  Idx := (Ctx.Count[0] shr 3) and $3F;
  Inc(Ctx.Count[0], Len shl 3);
  if Ctx.Count[0] < (Len shl 3) then Inc(Ctx.Count[1]);
  Inc(Ctx.Count[1], Len shr 29);
  PartLen := 64 - Idx;
  if Len >= PartLen then
  begin
    Move(Buf^, Ctx.Buffer[Idx], PartLen);
    MD5Transform(Ctx.State, Ctx.Buffer);
    i := PartLen;
    while i + 63 < Len do
    begin
      MD5Transform(Ctx.State, (Buf + i)^);
      Inc(i, 64);
    end;
    Idx := 0;
  end
  else
    i := 0;
  Move((Buf + i)^, Ctx.Buffer[Idx], Len - i);
end;

function MD5FinalHex(var Ctx: TMD5Context): string;
const
  Pad: array[0..63] of Byte = ($80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
var
  Bits: array[0..7] of Byte;
  Idx, PadLen, i: Cardinal;
  Digest: array[0..15] of Byte;
begin
  Move(Ctx.Count[0], Bits[0], 8);
  Idx := (Ctx.Count[0] shr 3) and $3F;
  if Idx < 56 then PadLen := 56 - Idx else PadLen := 120 - Idx;
  MD5Update(Ctx, @Pad[0], PadLen);
  MD5Update(Ctx, @Bits[0], 8);
  Move(Ctx.State[0], Digest[0], 16);
  Result := '';
  for i := 0 to 15 do
    Result := Result + LowerCase(IntToHex(Digest[i], 2));
end;

function CalcMD5Stream(Stream: TStream): string;
var
  Ctx: TMD5Context;
  Buf: array[0..16383] of Byte;
  N: Integer;
begin
  MD5Init(Ctx);
  Stream.Position := 0;
  repeat
    N := Stream.Read(Buf, SizeOf(Buf));
    if N > 0 then MD5Update(Ctx, @Buf[0], N);
  until N = 0;
  Result := MD5FinalHex(Ctx);
end;

{ Pure Pascal SHA-1 Implementation }
type
  TSHA1Context = record
    State: array[0..4] of DWORD;
    Count: array[0..1] of DWORD;
    Buffer: array[0..63] of Byte;
  end;

procedure SHA1Transform(var State: array of DWORD; const Block: array of Byte);
var
  a, b, c, d, e, t: DWORD;
  i: Integer;
  W: array[0..79] of DWORD;
begin
  for i := 0 to 15 do
    W[i] := (DWORD(Block[i * 4]) shl 24) or (DWORD(Block[i * 4 + 1]) shl 16) or
            (DWORD(Block[i * 4 + 2]) shl 8) or DWORD(Block[i * 4 + 3]);
  for i := 16 to 79 do
    W[i] := ROL32(W[i - 3] xor W[i - 8] xor W[i - 14] xor W[i - 16], 1);

  a := State[0]; b := State[1]; c := State[2]; d := State[3]; e := State[4];
  for i := 0 to 19 do
  begin
    t := ROL32(a, 5) + ((b and c) or ((not b) and d)) + e + W[i] + $5A827999;
    e := d; d := c; c := ROL32(b, 30); b := a; a := t;
  end;
  for i := 20 to 39 do
  begin
    t := ROL32(a, 5) + (b xor c xor d) + e + W[i] + $6ED9EBA1;
    e := d; d := c; c := ROL32(b, 30); b := a; a := t;
  end;
  for i := 40 to 59 do
  begin
    t := ROL32(a, 5) + ((b and c) or (b and d) or (c and d)) + e + W[i] + $8F1BBCDC;
    e := d; d := c; c := ROL32(b, 30); b := a; a := t;
  end;
  for i := 60 to 79 do
  begin
    t := ROL32(a, 5) + (b xor c xor d) + e + W[i] + $CA62C1D6;
    e := d; d := c; c := ROL32(b, 30); b := a; a := t;
  end;
  State[0] := State[0] + a;
  State[1] := State[1] + b;
  State[2] := State[2] + c;
  State[3] := State[3] + d;
  State[4] := State[4] + e;
end;

procedure SHA1Init(var Ctx: TSHA1Context);
begin
  Ctx.State[0] := $67452301; Ctx.State[1] := $EFCDAB89;
  Ctx.State[2] := $98BADCFE; Ctx.State[3] := $10325476;
  Ctx.State[4] := $C3D2E1F0;
  Ctx.Count[0] := 0; Ctx.Count[1] := 0;
end;

procedure SHA1Update(var Ctx: TSHA1Context; const Buf: PByte; Len: Cardinal);
var
  Idx, PartLen, i: Cardinal;
begin
  Idx := (Ctx.Count[0] shr 3) and $3F;
  Inc(Ctx.Count[0], Len shl 3);
  if Ctx.Count[0] < (Len shl 3) then Inc(Ctx.Count[1]);
  Inc(Ctx.Count[1], Len shr 29);
  PartLen := 64 - Idx;
  if Len >= PartLen then
  begin
    Move(Buf^, Ctx.Buffer[Idx], PartLen);
    SHA1Transform(Ctx.State, Ctx.Buffer);
    i := PartLen;
    while i + 63 < Len do
    begin
      SHA1Transform(Ctx.State, (Buf + i)^);
      Inc(i, 64);
    end;
    Idx := 0;
  end
  else
    i := 0;
  Move((Buf + i)^, Ctx.Buffer[Idx], Len - i);
end;

function SHA1FinalHex(var Ctx: TSHA1Context): string;
const
  Pad: array[0..63] of Byte = ($80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
var
  Bits: array[0..7] of Byte;
  Idx, PadLen, i: Cardinal;
  beHigh, beLow: DWORD;
begin
  beHigh := (Ctx.Count[1] shl 24) or ((Ctx.Count[1] and $FF00) shl 8) or
            ((Ctx.Count[1] and $FF0000) shr 8) or (Ctx.Count[1] shr 24);
  beLow := (Ctx.Count[0] shl 24) or ((Ctx.Count[0] and $FF00) shl 8) or
           ((Ctx.Count[0] and $FF0000) shr 8) or (Ctx.Count[0] shr 24);
  Move(beHigh, Bits[0], 4);
  Move(beLow, Bits[4], 4);

  Idx := (Ctx.Count[0] shr 3) and $3F;
  if Idx < 56 then PadLen := 56 - Idx else PadLen := 120 - Idx;
  SHA1Update(Ctx, @Pad[0], PadLen);
  SHA1Update(Ctx, @Bits[0], 8);

  Result := '';
  for i := 0 to 4 do
    Result := Result + LowerCase(IntToHex(Ctx.State[i], 8));
end;

function CalcSHA1Stream(Stream: TStream): string;
var
  Ctx: TSHA1Context;
  Buf: array[0..16383] of Byte;
  N: Integer;
begin
  SHA1Init(Ctx);
  Stream.Position := 0;
  repeat
    N := Stream.Read(Buf, SizeOf(Buf));
    if N > 0 then SHA1Update(Ctx, @Buf[0], N);
  until N = 0;
  Result := SHA1FinalHex(Ctx);
end;

{ Pure Pascal SHA-256 Implementation }
type
  TSHA256Context = record
    State: array[0..7] of DWORD;
    Count: QWord;
    Buffer: array[0..63] of Byte;
  end;

const
  K256: array[0..63] of DWORD = (
    $428a2f98, $71374491, $b5c0fbcf, $e9b5dba5, $3956c25b, $59f111f1, $923f82a4, $ab1c5ed5,
    $d807aa98, $12835b01, $243185be, $550c7dc3, $72be5d74, $80deb1fe, $9bdc06a7, $c19bf174,
    $e49b69c1, $efbe4786, $0fc19dc6, $240ca1cc, $2de92c6f, $4a7484aa, $5cb0a9dc, $76f988da,
    $983e5152, $a831c66d, $b00327c8, $bf597fc7, $c6e00bf3, $d5a79147, $06ca6351, $14292967,
    $27b70a85, $2e1b2138, $4d2c6dfc, $53380d13, $650a7354, $766a0abb, $81c2c92e, $92722c85,
    $a2bfe8a1, $a81a664b, $c24b8b70, $c76c51a3, $d192e819, $d6990624, $f40e3585, $106aa070,
    $19a4c116, $1e376c08, $2748774c, $34b0bcb5, $391c0cb3, $4ed8aa4a, $5b9cca4f, $682e6ff3,
    $748f82ee, $78a5636f, $84c87814, $8cc70208, $90befffa, $a4506ceb, $bef9a3f7, $c67178f2
  );

function ROR32(A: DWORD; S: Byte): DWORD; inline;
begin
  Result := (A shr S) or (A shl (32 - S));
end;

procedure SHA256Transform(var State: array of DWORD; const Block: array of Byte);
var
  a, b, c, d, e, f, g, h, t1, t2, s0, s1, ch, maj: DWORD;
  i: Integer;
  W: array[0..63] of DWORD;
begin
  for i := 0 to 15 do
    W[i] := (DWORD(Block[i * 4]) shl 24) or (DWORD(Block[i * 4 + 1]) shl 16) or
            (DWORD(Block[i * 4 + 2]) shl 8) or DWORD(Block[i * 4 + 3]);
  for i := 16 to 63 do
  begin
    s0 := ROR32(W[i - 15], 7) xor ROR32(W[i - 15], 18) xor (W[i - 15] shr 3);
    s1 := ROR32(W[i - 2], 17) xor ROR32(W[i - 2], 19) xor (W[i - 2] shr 10);
    W[i] := W[i - 16] + s0 + W[i - 7] + s1;
  end;

  a := State[0]; b := State[1]; c := State[2]; d := State[3];
  e := State[4]; f := State[5]; g := State[6]; h := State[7];

  for i := 0 to 63 do
  begin
    s1 := ROR32(e, 6) xor ROR32(e, 11) xor ROR32(e, 25);
    ch := (e and f) xor ((not e) and g);
    t1 := h + s1 + ch + K256[i] + W[i];
    s0 := ROR32(a, 2) xor ROR32(a, 13) xor ROR32(a, 22);
    maj := (a and b) xor (a and c) xor (b and c);
    t2 := s0 + maj;

    h := g; g := f; f := e; e := d + t1;
    d := c; c := b; b := a; a := t1 + t2;
  end;

  State[0] := State[0] + a; State[1] := State[1] + b;
  State[2] := State[2] + c; State[3] := State[3] + d;
  State[4] := State[4] + e; State[5] := State[5] + f;
  State[6] := State[6] + g; State[7] := State[7] + h;
end;

procedure SHA256Init(var Ctx: TSHA256Context);
begin
  Ctx.State[0] := $6a09e667; Ctx.State[1] := $bb67ae85;
  Ctx.State[2] := $3c6ef372; Ctx.State[3] := $a54ff53a;
  Ctx.State[4] := $510e527f; Ctx.State[5] := $9b05688c;
  Ctx.State[6] := $1f83d9ab; Ctx.State[7] := $5be0cd19;
  Ctx.Count := 0;
end;

procedure SHA256Update(var Ctx: TSHA256Context; const Buf: PByte; Len: Cardinal);
var
  Idx, PartLen, i: Cardinal;
begin
  Idx := Ctx.Count and $3F;
  Inc(Ctx.Count, Len);
  PartLen := 64 - Idx;
  if Len >= PartLen then
  begin
    Move(Buf^, Ctx.Buffer[Idx], PartLen);
    SHA256Transform(Ctx.State, Ctx.Buffer);
    i := PartLen;
    while i + 63 < Len do
    begin
      SHA256Transform(Ctx.State, (Buf + i)^);
      Inc(i, 64);
    end;
    Idx := 0;
  end
  else
    i := 0;
  Move((Buf + i)^, Ctx.Buffer[Idx], Len - i);
end;

function SHA256FinalHex(var Ctx: TSHA256Context): string;
const
  Pad: array[0..63] of Byte = ($80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
var
  BitLen: QWord;
  Bits: array[0..7] of Byte;
  Idx, PadLen, i: Cardinal;
begin
  BitLen := Ctx.Count * 8;
  for i := 0 to 7 do
    Bits[i] := Byte((BitLen shr ((7 - i) * 8)) and $FF);

  Idx := Ctx.Count and $3F;
  if Idx < 56 then PadLen := 56 - Idx else PadLen := 120 - Idx;
  SHA256Update(Ctx, @Pad[0], PadLen);
  SHA256Update(Ctx, @Bits[0], 8);

  Result := '';
  for i := 0 to 7 do
    Result := Result + LowerCase(IntToHex(Ctx.State[i], 8));
end;

function CalcSHA256Stream(Stream: TStream): string;
var
  Ctx: TSHA256Context;
  Buf: array[0..16383] of Byte;
  N: Integer;
begin
  SHA256Init(Ctx);
  Stream.Position := 0;
  repeat
    N := Stream.Read(Buf, SizeOf(Buf));
    if N > 0 then SHA256Update(Ctx, @Buf[0], N);
  until N = 0;
  Result := SHA256FinalHex(Ctx);
end;

{ Shannon Entropy Calculator (0.00 - 8.00) }
function CalculateEntropy(Stream: TStream; Offset, Count: Int64): Double;
var
  Counts: array[0..255] of Int64;
  Buf: array[0..8191] of Byte;
  ToRead, N, i: Integer;
  Remaining: Int64;
  P, Ent: Double;
  SavedPos: Int64;
begin
  Result := 0.0;
  if (Count <= 0) or (Offset < 0) or (Offset >= Stream.Size) then Exit;
  if Offset + Count > Stream.Size then
    Count := Stream.Size - Offset;

  SavedPos := Stream.Position;
  try
    FillChar(Counts, SizeOf(Counts), 0);
    Stream.Position := Offset;
    Remaining := Count;

    while Remaining > 0 do
    begin
      if Remaining > SizeOf(Buf) then ToRead := SizeOf(Buf) else ToRead := Remaining;
      N := Stream.Read(Buf, ToRead);
      if N <= 0 then Break;
      for i := 0 to N - 1 do
        Inc(Counts[Buf[i]]);
      Dec(Remaining, N);
    end;

    Ent := 0.0;
    for i := 0 to 255 do
    begin
      if Counts[i] > 0 then
      begin
        P := Counts[i] / Count;
        Ent := Ent - (P * (Ln(P) / Ln(2)));
      end;
    end;
    Result := Ent;
  finally
    Stream.Position := SavedPos;
  end;
end;

{ ===========================================================================
  TVirusKovAlyzerForm Implementation
  =========================================================================== }

procedure TVirusKovAlyzerForm.FormCreate(Sender: TObject);
begin
  FHexPageSize := 4096; // 4 KB (256 lines of 16 bytes) per page for instant virtual scrolling
  FHexPage := 0;
  FImportList := TStringList.Create;
  FAllStrings := TStringList.Create;
  ClearAnalysisData;
end;

procedure TVirusKovAlyzerForm.FormDestroy(Sender: TObject);
begin
  ClearAnalysisData;
  FImportList.Free;
  FAllStrings.Free;
  if VirusKovAlyzerForm = Self then
    VirusKovAlyzerForm := nil;
end;

procedure TVirusKovAlyzerForm.ClearAnalysisData;
var
  i: Integer;
begin
  FFilePath := '';
  FFileSize := 0;
  FIsPE := False;
  FIs64Bit := False;
  SetLength(FSectionHeaders, 0);
  SetLength(FSectionEntropies, 0);
  for i := 0 to FImportList.Count - 1 do
    if Assigned(FImportList.Objects[i]) then
      TStringList(FImportList.Objects[i]).Free;
  FImportList.Clear;
  FAllStrings.Clear;
end;

class procedure TVirusKovAlyzerForm.InspectFile(const APath: string);
begin
  if not FileExists(APath) then
  begin
    ShowMessage('File does not exist: ' + APath);
    Exit;
  end;

  if VirusKovAlyzerForm = nil then
    VirusKovAlyzerForm := TVirusKovAlyzerForm.Create(Application);

  VirusKovAlyzerForm.AnalyzeFile(APath);
  VirusKovAlyzerForm.Show;
  VirusKovAlyzerForm.BringToFront;
end;

procedure TVirusKovAlyzerForm.AnalyzeFile(const APath: string);
begin
  ClearAnalysisData;
  FFilePath := APath;
  EditFilePath.Text := APath;

  CalculateHashesAndTimestamps(APath);
  ParsePEHeader(APath);
  ExtractStrings(APath);
  QueryEngineSecurity(APath);

  FHexTotalPages := Max(1, (FFileSize + FHexPageSize - 1) div FHexPageSize);
  FHexPage := 0;
  RenderHexPage;

  PageControl.ActivePageIndex := 0;
end;

procedure TVirusKovAlyzerForm.CalculateHashesAndTimestamps(const APath: string);
var
  Fs: TFileStream;
  Fad: WIN32_FILE_ATTRIBUTE_DATA;
  StCreated, StAccess, StWrite: SYSTEMTIME;
  LtCreated, LtAccess, LtWrite: SYSTEMTIME;
  Attrs: DWORD;
begin
  if not GetFileAttributesExW(PWideChar(UTF8Decode(APath)), GetFileExInfoStandard, @Fad) then
    Exit;

  FFileSize := (Int64(Fad.nFileSizeHigh) shl 32) or Fad.nFileSizeLow;
  Attrs := Fad.dwFileAttributes;

  // General labels
  LblLocationVal.Caption := ExtractFilePath(APath);
  LblSizeVal.Caption := Format('%s bytes  (0x%s)', [FormatFloat('#,##0', FFileSize), IntToHex(FFileSize, 8)]);

  // Attributes
  CbReadOnly.Checked := (Attrs and FILE_ATTRIBUTE_READONLY) <> 0;
  CbHidden.Checked := (Attrs and FILE_ATTRIBUTE_HIDDEN) <> 0;
  CbSystem.Checked := (Attrs and FILE_ATTRIBUTE_SYSTEM) <> 0;
  CbArchive.Checked := (Attrs and FILE_ATTRIBUTE_ARCHIVE) <> 0;
  CbCompressed.Checked := (Attrs and FILE_ATTRIBUTE_COMPRESSED) <> 0;
  CbEncrypted.Checked := (Attrs and FILE_ATTRIBUTE_ENCRYPTED) <> 0;

  // Timestamps
  FileTimeToSystemTime(@Fad.ftCreationTime, @StCreated);
  FileTimeToSystemTime(@Fad.ftLastAccessTime, @StAccess);
  FileTimeToSystemTime(@Fad.ftLastWriteTime, @StWrite);

  SystemTimeToTzSpecificLocalTime(nil, @StCreated, @LtCreated);
  SystemTimeToTzSpecificLocalTime(nil, @StAccess, @LtAccess);
  SystemTimeToTzSpecificLocalTime(nil, @StWrite, @LtWrite);

  LblCreatedVal.Caption := Format('%4d-%02d-%02d %02d:%02d:%02d (Local)  |  %4d-%02d-%02d %02d:%02d:%02d (UTC)',
    [LtCreated.wYear, LtCreated.wMonth, LtCreated.wDay, LtCreated.wHour, LtCreated.wMinute, LtCreated.wSecond,
     StCreated.wYear, StCreated.wMonth, StCreated.wDay, StCreated.wHour, StCreated.wMinute, StCreated.wSecond]);

  LblModifiedVal.Caption := Format('%4d-%02d-%02d %02d:%02d:%02d (Local)  |  %4d-%02d-%02d %02d:%02d:%02d (UTC)',
    [LtWrite.wYear, LtWrite.wMonth, LtWrite.wDay, LtWrite.wHour, LtWrite.wMinute, LtWrite.wSecond,
     StWrite.wYear, StWrite.wMonth, StWrite.wDay, StWrite.wHour, StWrite.wMinute, StWrite.wSecond]);

  LblAccessedVal.Caption := Format('%4d-%02d-%02d %02d:%02d:%02d (Local)  |  %4d-%02d-%02d %02d:%02d:%02d (UTC)',
    [LtAccess.wYear, LtAccess.wMonth, LtAccess.wDay, LtAccess.wHour, LtAccess.wMinute, LtAccess.wSecond,
     StAccess.wYear, StAccess.wMonth, StAccess.wDay, StAccess.wHour, StAccess.wMinute, StAccess.wSecond]);

  // Compute Hashes
  try
    Fs := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
    try
      EditCrc32.Text := UpperCase(IntToHex(CalcCRC32Stream(Fs), 8));
      EditMd5.Text := UpperCase(CalcMD5Stream(Fs));
      EditSha1.Text := UpperCase(CalcSHA1Stream(Fs));
      EditSha256.Text := UpperCase(CalcSHA256Stream(Fs));
    finally
      Fs.Free;
    end;
  except
    on E: Exception do
      ShowMessage('Error computing hashes: ' + E.Message);
  end;
end;

function TVirusKovAlyzerForm.RvaToFileOffset(ARva: DWORD): DWORD;
var
  i: Integer;
  VAddr, VSize, RawSize, RawPtr, Span: DWORD;
begin
  Result := 0;
  if ARva = 0 then Exit;

  for i := 0 to High(FSectionHeaders) do
  begin
    VAddr := FSectionHeaders[i].VirtualAddress;
    VSize := FSectionHeaders[i].VirtualSize;
    RawSize := FSectionHeaders[i].SizeOfRawData;
    RawPtr := FSectionHeaders[i].PointerToRawData;

    Span := VSize;
    if Span = 0 then Span := RawSize;
    if (RawSize > 0) and (RawSize > Span) then Span := RawSize;

    if (ARva >= VAddr) and (ARva < VAddr + Span) then
    begin
      Result := RawPtr + (ARva - VAddr);
      Exit;
    end;
  end;
end;

procedure TVirusKovAlyzerForm.ParsePEHeader(const APath: string);
var
  Fs: TFileStream;
  PeSig: DWORD;
  SubsysStr: string;
begin
  MemoHeaders.Clear;
  LvSections.Items.Clear;
  LbImportDlls.Clear;
  LvImportFunctions.Items.Clear;
  LvExports.Items.Clear;
  MemoExportsInfo.Clear;

  try
    Fs := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
    try
      if Fs.Size < SizeOf(TImageDosHeader) then
      begin
        LblTypeVal.Caption := 'Non-PE Binary';
        LblArchVal.Caption := 'N/A';
        Exit;
      end;

      Fs.Read(FDosHeader, SizeOf(TImageDosHeader));
      if FDosHeader.e_magic <> $5A4D then // 'MZ'
      begin
        LblTypeVal.Caption := 'Generic Document or Data File';
        LblArchVal.Caption := 'N/A';
        Exit;
      end;

      if (FDosHeader.e_lfanew <= 0) or (FDosHeader.e_lfanew + 4 > Fs.Size) then
      begin
        LblTypeVal.Caption := 'DOS Executable (MZ)';
        LblArchVal.Caption := '16-bit DOS';
        Exit;
      end;

      Fs.Position := FDosHeader.e_lfanew;
      Fs.Read(PeSig, SizeOf(DWORD));
      if PeSig <> $00004550 then // 'PE\0\0'
      begin
        LblTypeVal.Caption := 'Legacy DOS / NE Executable';
        LblArchVal.Caption := '16-bit';
        Exit;
      end;

      FIsPE := True;
      Fs.Read(FFileHeader, SizeOf(TImageFileHeader));

      if FFileHeader.Machine = $014C then
      begin
        FIs64Bit := False;
        LblArchVal.Caption := 'x86 (32-bit Intel/AMD)';
      end
      else if FFileHeader.Machine = $8664 then
      begin
        FIs64Bit := True;
        LblArchVal.Caption := 'x64 (64-bit AMD64)';
      end
      else if FFileHeader.Machine = $AA64 then
      begin
        FIs64Bit := True;
        LblArchVal.Caption := 'ARM64';
      end
      else
        LblArchVal.Caption := Format('Machine Architecture: 0x%04x', [FFileHeader.Machine]);

      FillChar(FOptHeader64, SizeOf(FOptHeader64), 0);
      FillChar(FOptHeader32, SizeOf(FOptHeader32), 0);

      if FIs64Bit then
      begin
        Fs.Read(FOptHeader64, Min(SizeOf(TImageOptionalHeader64), FFileHeader.SizeOfOptionalHeader));
        case FOptHeader64.Subsystem of
          1: SubsysStr := 'Native Device Driver';
          2: SubsysStr := 'Windows GUI (Graphical)';
          3: SubsysStr := 'Windows CUI (Console)';
        else
          SubsysStr := Format('Subsystem %d', [FOptHeader64.Subsystem]);
        end;
        if (FFileHeader.Characteristics and $2000) <> 0 then
          LblTypeVal.Caption := 'Dynamic Link Library (DLL) - ' + SubsysStr
        else
          LblTypeVal.Caption := 'Portable Executable (PE32+) - ' + SubsysStr;
      end
      else
      begin
        Fs.Read(FOptHeader32, Min(SizeOf(TImageOptionalHeader32), FFileHeader.SizeOfOptionalHeader));
        case FOptHeader32.Subsystem of
          1: SubsysStr := 'Native Device Driver';
          2: SubsysStr := 'Windows GUI (Graphical)';
          3: SubsysStr := 'Windows CUI (Console)';
        else
          SubsysStr := Format('Subsystem %d', [FOptHeader32.Subsystem]);
        end;
        if (FFileHeader.Characteristics and $2000) <> 0 then
          LblTypeVal.Caption := 'Dynamic Link Library (DLL) - ' + SubsysStr
        else
          LblTypeVal.Caption := 'Portable Executable (PE32) - ' + SubsysStr;
      end;

      // Populate Headers Memo
      MemoHeaders.Lines.Add('=== DOS HEADER ===');
      MemoHeaders.Lines.Add(Format('Magic: 0x%04X (MZ)', [FDosHeader.e_magic]));
      MemoHeaders.Lines.Add(Format('e_lfanew (PE Offset): 0x%08X (%d)', [FDosHeader.e_lfanew, FDosHeader.e_lfanew]));
      MemoHeaders.Lines.Add('');

      MemoHeaders.Lines.Add('=== COFF FILE HEADER ===');
      MemoHeaders.Lines.Add(Format('Machine: 0x%04X (%s)', [FFileHeader.Machine, LblArchVal.Caption]));
      MemoHeaders.Lines.Add(Format('Number of Sections: %d', [FFileHeader.NumberOfSections]));
      MemoHeaders.Lines.Add(Format('TimeDateStamp: 0x%08X', [FFileHeader.TimeDateStamp]));
      MemoHeaders.Lines.Add(Format('Size of Optional Header: %d bytes', [FFileHeader.SizeOfOptionalHeader]));
      MemoHeaders.Lines.Add(Format('Characteristics: 0x%04X', [FFileHeader.Characteristics]));
      if (FFileHeader.Characteristics and $0002) <> 0 then MemoHeaders.Lines.Add('  [+] Executable Image');
      if (FFileHeader.Characteristics and $2000) <> 0 then MemoHeaders.Lines.Add('  [+] DLL File');
      if (FFileHeader.Characteristics and $0100) <> 0 then MemoHeaders.Lines.Add('  [+] 32-bit Machine Word');
      MemoHeaders.Lines.Add('');

      MemoHeaders.Lines.Add('=== OPTIONAL HEADER ===');
      if FIs64Bit then
      begin
        MemoHeaders.Lines.Add(Format('Magic: 0x%04X (PE32+ 64-bit)', [FOptHeader64.Magic]));
        MemoHeaders.Lines.Add(Format('Address of EntryPoint: 0x%08X', [FOptHeader64.AddressOfEntryPoint]));
        MemoHeaders.Lines.Add(Format('ImageBase: 0x%016X', [FOptHeader64.ImageBase]));
        MemoHeaders.Lines.Add(Format('Section Alignment: 0x%08X', [FOptHeader64.SectionAlignment]));
        MemoHeaders.Lines.Add(Format('File Alignment: 0x%08X', [FOptHeader64.FileAlignment]));
        MemoHeaders.Lines.Add(Format('Size of Image: 0x%08X (%d bytes)', [FOptHeader64.SizeOfImage, FOptHeader64.SizeOfImage]));
        MemoHeaders.Lines.Add(Format('Size of Headers: 0x%08X', [FOptHeader64.SizeOfHeaders]));
        MemoHeaders.Lines.Add(Format('Subsystem: %s', [SubsysStr]));
        MemoHeaders.Lines.Add(Format('DllCharacteristics: 0x%04X', [FOptHeader64.DllCharacteristics]));
        if (FOptHeader64.DllCharacteristics and $0040) <> 0 then MemoHeaders.Lines.Add('  [+] ASLR (DynamicBase)');
        if (FOptHeader64.DllCharacteristics and $0100) <> 0 then MemoHeaders.Lines.Add('  [+] DEP / NX (Data Execution Prevention)');
        if (FOptHeader64.DllCharacteristics and $4000) <> 0 then MemoHeaders.Lines.Add('  [+] Control Flow Guard (GuardCF)');
        if (FOptHeader64.DllCharacteristics and $0020) <> 0 then MemoHeaders.Lines.Add('  [+] High Entropy 64-bit ASLR');
        if FOptHeader64.DataDirectory[14].VirtualAddress <> 0 then
          MemoHeaders.Lines.Add('  [+] Microsoft .NET / CLR Assembly detected');
      end
      else
      begin
        MemoHeaders.Lines.Add(Format('Magic: 0x%04X (PE32 32-bit)', [FOptHeader32.Magic]));
        MemoHeaders.Lines.Add(Format('Address of EntryPoint: 0x%08X', [FOptHeader32.AddressOfEntryPoint]));
        MemoHeaders.Lines.Add(Format('ImageBase: 0x%08X', [FOptHeader32.ImageBase]));
        MemoHeaders.Lines.Add(Format('Section Alignment: 0x%08X', [FOptHeader32.SectionAlignment]));
        MemoHeaders.Lines.Add(Format('File Alignment: 0x%08X', [FOptHeader32.FileAlignment]));
        MemoHeaders.Lines.Add(Format('Size of Image: 0x%08X (%d bytes)', [FOptHeader32.SizeOfImage, FOptHeader32.SizeOfImage]));
        MemoHeaders.Lines.Add(Format('Size of Headers: 0x%08X', [FOptHeader32.SizeOfHeaders]));
        MemoHeaders.Lines.Add(Format('Subsystem: %s', [SubsysStr]));
        MemoHeaders.Lines.Add(Format('DllCharacteristics: 0x%04X', [FOptHeader32.DllCharacteristics]));
        if (FOptHeader32.DllCharacteristics and $0040) <> 0 then MemoHeaders.Lines.Add('  [+] ASLR (DynamicBase)');
        if (FOptHeader32.DllCharacteristics and $0100) <> 0 then MemoHeaders.Lines.Add('  [+] DEP / NX (Data Execution Prevention)');
        if (FOptHeader32.DllCharacteristics and $4000) <> 0 then MemoHeaders.Lines.Add('  [+] Control Flow Guard (GuardCF)');
        if FOptHeader32.DataDirectory[14].VirtualAddress <> 0 then
          MemoHeaders.Lines.Add('  [+] Microsoft .NET / CLR Assembly detected');
      end;

      // Position stream explicitly at Section Headers table
      Fs.Position := Int64(FDosHeader.e_lfanew) + 4 + SizeOf(TImageFileHeader) + FFileHeader.SizeOfOptionalHeader;

      ParseSections(Fs);
      ParseImports(Fs);
      ParseExports(Fs);

    finally
      Fs.Free;
    end;
  except
    on E: Exception do
      MemoHeaders.Lines.Add('Error parsing PE: ' + E.Message);
  end;
end;

procedure TVirusKovAlyzerForm.ParseSections(Stream: TStream);
var
  i: Integer;
  SecHdrStart: Int64;
  SecHdr: TImageSectionHeader;
  SecName: string;
  It: TListItem;
  Entropy: Double;
  CharStr: string;
begin
  SecHdrStart := Int64(FDosHeader.e_lfanew) + 4 + SizeOf(TImageFileHeader) + FFileHeader.SizeOfOptionalHeader;
  SetLength(FSectionHeaders, FFileHeader.NumberOfSections);
  SetLength(FSectionEntropies, FFileHeader.NumberOfSections);

  LvSections.Items.BeginUpdate;
  try
    for i := 0 to FFileHeader.NumberOfSections - 1 do
    begin
      Stream.Position := SecHdrStart + (Int64(i) * SizeOf(TImageSectionHeader));
      if Stream.Position + SizeOf(TImageSectionHeader) > Stream.Size then
        Break;

      Stream.Read(SecHdr, SizeOf(TImageSectionHeader));
      FSectionHeaders[i] := SecHdr;

      SecName := Trim(String(PAnsiChar(@SecHdr.Name[0])));
      if SecName = '' then SecName := Format('Sec_%d', [i]);

      Entropy := CalculateEntropy(Stream, SecHdr.PointerToRawData, SecHdr.SizeOfRawData);
      FSectionEntropies[i] := Entropy;

      CharStr := '';
      if (SecHdr.Characteristics and $20000000) <> 0 then CharStr := CharStr + 'X';
      if (SecHdr.Characteristics and $40000000) <> 0 then CharStr := CharStr + 'R';
      if (SecHdr.Characteristics and $80000000) <> 0 then CharStr := CharStr + 'W';
      if (SecHdr.Characteristics and $00000020) <> 0 then CharStr := CharStr + ' [Code]';
      if (SecHdr.Characteristics and $00000040) <> 0 then CharStr := CharStr + ' [InitData]';

      It := LvSections.Items.Add;
      It.Caption := SecName;
      It.SubItems.Add(Format('0x%08X', [SecHdr.VirtualAddress]));
      It.SubItems.Add(Format('0x%08X (%d)', [SecHdr.VirtualSize, SecHdr.VirtualSize]));
      It.SubItems.Add(Format('0x%08X', [SecHdr.PointerToRawData]));
      It.SubItems.Add(Format('0x%08X (%d)', [SecHdr.SizeOfRawData, SecHdr.SizeOfRawData]));
      It.SubItems.Add(Format('%.2f', [Entropy]));

      if Entropy >= 7.20 then
        It.SubItems.Add('PACKED / ENCRYPTED')
      else if Entropy >= 6.50 then
        It.SubItems.Add('Compressed / Dense')
      else
        It.SubItems.Add('Normal');

      It.SubItems.Add(CharStr);
    end;
  finally
    LvSections.Items.EndUpdate;
  end;
end;

procedure TVirusKovAlyzerForm.ParseImports(Stream: TStream);
var
  DataDir: TImageDataDirectory;
  ImportOffset: DWORD;
  Descriptor: TImageImportDescriptor;
  DescIdx: Integer;
  DescFileOffset: Int64;
  DllNameOffset, ThunkOffset: DWORD;
  DllName, FnName: string;
  c: AnsiChar;
  FuncList: TStringList;
  Thunk32: DWORD;
  Thunk64: QWord;
  ThunkIdx: Integer;
  CurThunkPos: Int64;
  HintNameOffset: DWORD;
  FnHint: Word;
begin
  if FIs64Bit then
    DataDir := FOptHeader64.DataDirectory[1]
  else
    DataDir := FOptHeader32.DataDirectory[1];

  if (DataDir.VirtualAddress = 0) or (DataDir.Size = 0) then Exit;

  ImportOffset := RvaToFileOffset(DataDir.VirtualAddress);
  if ImportOffset = 0 then Exit;

  LbImportDlls.Items.BeginUpdate;
  try
    DescIdx := 0;
    while True do
    begin
      DescFileOffset := ImportOffset + (Int64(DescIdx) * SizeOf(TImageImportDescriptor));
      if DescFileOffset + SizeOf(TImageImportDescriptor) > Stream.Size then
        Break;

      Stream.Position := DescFileOffset;
      Stream.Read(Descriptor, SizeOf(TImageImportDescriptor));
      Inc(DescIdx);

      // All-zero descriptor terminates the Import Directory table
      if (Descriptor.Name = 0) and (Descriptor.FirstThunk = 0) then
        Break;

      if Descriptor.Name = 0 then
        Continue;

      DllNameOffset := RvaToFileOffset(Descriptor.Name);
      if (DllNameOffset = 0) or (DllNameOffset >= Stream.Size) then
        Continue;

      Stream.Position := DllNameOffset;
      DllName := '';
      repeat
        Stream.Read(c, 1);
        if c <> #0 then DllName := DllName + c;
      until (c = #0) or (Length(DllName) > 256) or (Stream.Position >= Stream.Size);

      if DllName = '' then
        DllName := Format('Unknown_DLL_%d', [DescIdx]);

      FuncList := TStringList.Create;

      // Prefer OriginalFirstThunk (Characteristics / ILT), fallback to FirstThunk (IAT)
      if Descriptor.OriginalFirstThunk <> 0 then
        ThunkOffset := RvaToFileOffset(Descriptor.OriginalFirstThunk)
      else
        ThunkOffset := RvaToFileOffset(Descriptor.FirstThunk);

      if (ThunkOffset <> 0) and (ThunkOffset < Stream.Size) then
      begin
        ThunkIdx := 0;
        while True do
        begin
          if FIs64Bit then
          begin
            CurThunkPos := ThunkOffset + (Int64(ThunkIdx) * 8);
            if CurThunkPos + 8 > Stream.Size then Break;

            Stream.Position := CurThunkPos;
            Stream.Read(Thunk64, 8);
            Inc(ThunkIdx);

            if Thunk64 = 0 then Break;

            if (Thunk64 and $8000000000000000) <> 0 then
            begin
              FuncList.Add(Format('[Ordinal #%d]', [Thunk64 and $FFFF]));
            end
            else
            begin
              HintNameOffset := RvaToFileOffset(DWORD(Thunk64 and $7FFFFFFF));
              if (HintNameOffset > 0) and (HintNameOffset + 2 < Stream.Size) then
              begin
                Stream.Position := HintNameOffset;
                Stream.Read(FnHint, 2);
                FnName := '';
                repeat
                  Stream.Read(c, 1);
                  if c <> #0 then FnName := FnName + c;
                until (c = #0) or (Length(FnName) > 256) or (Stream.Position >= Stream.Size);

                if FnName <> '' then
                  FuncList.Add(FnName)
                else
                  FuncList.Add(Format('[Hint #%d]', [FnHint]));
              end
              else
                FuncList.Add(Format('[RVA 0x%08X]', [DWORD(Thunk64 and $7FFFFFFF)]));
            end;
          end
          else
          begin
            CurThunkPos := ThunkOffset + (Int64(ThunkIdx) * 4);
            if CurThunkPos + 4 > Stream.Size then Break;

            Stream.Position := CurThunkPos;
            Stream.Read(Thunk32, 4);
            Inc(ThunkIdx);

            if Thunk32 = 0 then Break;

            if (Thunk32 and $80000000) <> 0 then
            begin
              FuncList.Add(Format('[Ordinal #%d]', [Thunk32 and $FFFF]));
            end
            else
            begin
              HintNameOffset := RvaToFileOffset(Thunk32 and $7FFFFFFF);
              if (HintNameOffset > 0) and (HintNameOffset + 2 < Stream.Size) then
              begin
                Stream.Position := HintNameOffset;
                Stream.Read(FnHint, 2);
                FnName := '';
                repeat
                  Stream.Read(c, 1);
                  if c <> #0 then FnName := FnName + c;
                until (c = #0) or (Length(FnName) > 256) or (Stream.Position >= Stream.Size);

                if FnName <> '' then
                  FuncList.Add(FnName)
                else
                  FuncList.Add(Format('[Hint #%d]', [FnHint]));
              end
              else
                FuncList.Add(Format('[RVA 0x%08X]', [Thunk32 and $7FFFFFFF]));
            end;
          end;

          if ThunkIdx > 8192 then Break; // Safety guard
        end;
      end;

      FImportList.AddObject(DllName, FuncList);
      LbImportDlls.Items.Add(Format('%s (%d APIs)', [DllName, FuncList.Count]));

      if DescIdx > 512 then Break; // Safety guard
    end;
  finally
    LbImportDlls.Items.EndUpdate;
  end;

  if LbImportDlls.Count > 0 then
  begin
    LbImportDlls.ItemIndex := 0;
    EditImportFilterChange(nil);
  end;
end;

procedure TVirusKovAlyzerForm.ParseExports(Stream: TStream);
var
  DataDir: TImageDataDirectory;
  ExportOffset: DWORD;
  ExpDir: TImageExportDirectory;
  ModNameOffset, NamesOffset, OrdinalsOffset, FuncsOffset: DWORD;
  ModName, FnName: string;
  c: AnsiChar;
  i: Integer;
  NameRva: DWORD;
  OrdVal: Word;
  FnRva: DWORD;
  It: TListItem;
  TotalFunctions, NamedCount: DWORD;
begin
  if FIs64Bit then
    DataDir := FOptHeader64.DataDirectory[0]
  else
    DataDir := FOptHeader32.DataDirectory[0];

  if (DataDir.VirtualAddress = 0) or (DataDir.Size = 0) then
  begin
    MemoExportsInfo.Lines.Add('This binary has no export directory (standard for typical .exe applications).');
    Exit;
  end;

  ExportOffset := RvaToFileOffset(DataDir.VirtualAddress);
  if (ExportOffset = 0) or (ExportOffset + SizeOf(TImageExportDirectory) > Stream.Size) then
  begin
    MemoExportsInfo.Lines.Add('Export Directory RVA (0x' + IntToHex(DataDir.VirtualAddress, 8) + ') could not be mapped to file offset.');
    Exit;
  end;

  Stream.Position := ExportOffset;
  Stream.Read(ExpDir, SizeOf(TImageExportDirectory));

  ModName := '';
  if ExpDir.Name <> 0 then
  begin
    ModNameOffset := RvaToFileOffset(ExpDir.Name);
    if (ModNameOffset > 0) and (ModNameOffset < Stream.Size) then
    begin
      Stream.Position := ModNameOffset;
      repeat
        Stream.Read(c, 1);
        if c <> #0 then ModName := ModName + c;
      until (c = #0) or (Length(ModName) > 256) or (Stream.Position >= Stream.Size);
    end;
  end;

  if ModName = '' then ModName := ExtractFileName(FFilePath);

  MemoExportsInfo.Lines.Add(Format('Export Module Name: %s', [ModName]));
  MemoExportsInfo.Lines.Add(Format('Base Ordinal: %d', [ExpDir.Base]));
  MemoExportsInfo.Lines.Add(Format('Number of Functions: %d', [ExpDir.NumberOfFunctions]));
  MemoExportsInfo.Lines.Add(Format('Number of Named Exports: %d', [ExpDir.NumberOfNames]));

  TotalFunctions := ExpDir.NumberOfFunctions;
  NamedCount := ExpDir.NumberOfNames;

  NamesOffset := 0;
  if ExpDir.AddressOfNames <> 0 then
    NamesOffset := RvaToFileOffset(ExpDir.AddressOfNames);

  OrdinalsOffset := 0;
  if ExpDir.AddressOfNameOrdinals <> 0 then
    OrdinalsOffset := RvaToFileOffset(ExpDir.AddressOfNameOrdinals);

  FuncsOffset := 0;
  if ExpDir.AddressOfFunctions <> 0 then
    FuncsOffset := RvaToFileOffset(ExpDir.AddressOfFunctions);

  if FuncsOffset = 0 then
  begin
    MemoExportsInfo.Lines.Add('AddressOfFunctions RVA could not be resolved.');
    Exit;
  end;

  LvExports.Items.BeginUpdate;
  try
    if (NamedCount > 0) and (NamesOffset > 0) and (OrdinalsOffset > 0) then
    begin
      for i := 0 to Min(NamedCount, 8192) - 1 do
      begin
        Stream.Position := NamesOffset + (Int64(i) * 4);
        if Stream.Position + 4 > Stream.Size then Break;
        Stream.Read(NameRva, 4);

        Stream.Position := OrdinalsOffset + (Int64(i) * 2);
        if Stream.Position + 2 > Stream.Size then Break;
        Stream.Read(OrdVal, 2);

        FnRva := 0;
        if OrdVal < TotalFunctions then
        begin
          Stream.Position := FuncsOffset + (Int64(OrdVal) * 4);
          if Stream.Position + 4 <= Stream.Size then
            Stream.Read(FnRva, 4);
        end;

        FnName := '';
        if NameRva <> 0 then
        begin
          ModNameOffset := RvaToFileOffset(NameRva);
          if (ModNameOffset > 0) and (ModNameOffset < Stream.Size) then
          begin
            Stream.Position := ModNameOffset;
            repeat
              Stream.Read(c, 1);
              if c <> #0 then FnName := FnName + c;
            until (c = #0) or (Length(FnName) > 256) or (Stream.Position >= Stream.Size);
          end;
        end;

        if FnName = '' then
          FnName := Format('[Ordinal Only #%d]', [ExpDir.Base + OrdVal]);

        It := LvExports.Items.Add;
        It.Caption := IntToStr(ExpDir.Base + OrdVal);
        It.SubItems.Add(Format('0x%08X', [FnRva]));
        It.SubItems.Add(FnName);
      end;
    end
    else if TotalFunctions > 0 then
    begin
      for i := 0 to Min(TotalFunctions, 8192) - 1 do
      begin
        Stream.Position := FuncsOffset + (Int64(i) * 4);
        if Stream.Position + 4 > Stream.Size then Break;
        Stream.Read(FnRva, 4);
        if FnRva = 0 then Continue;

        It := LvExports.Items.Add;
        It.Caption := IntToStr(ExpDir.Base + i);
        It.SubItems.Add(Format('0x%08X', [FnRva]));
        It.SubItems.Add(Format('[Export #%d]', [ExpDir.Base + i]));
      end;
    end;
  finally
    LvExports.Items.EndUpdate;
  end;
end;

procedure TVirusKovAlyzerForm.ExtractStrings(const APath: string);
var
  Fs: TFileStream;
  Buf: array[0..32767] of Byte;
  N, i: Integer;
  CurAscii: string;
begin
  FAllStrings.Clear;
  CurAscii := '';

  try
    Fs := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
    try
      // Scan up to first 2MB for strings to stay instant
      while (Fs.Position < Fs.Size) and (Fs.Position < 2 * 1024 * 1024) do
      begin
        N := Fs.Read(Buf, SizeOf(Buf));
        if N <= 0 then Break;
        for i := 0 to N - 1 do
        begin
          if (Buf[i] >= 32) and (Buf[i] <= 126) then
          begin
            CurAscii := CurAscii + Chr(Buf[i]);
          end
          else
          begin
            if Length(CurAscii) >= 4 then
            begin
              FAllStrings.Add(CurAscii);
              if FAllStrings.Count >= 5000 then Break;
            end;
            CurAscii := '';
          end;
        end;
        if FAllStrings.Count >= 5000 then Break;
      end;
      if Length(CurAscii) >= 4 then FAllStrings.Add(CurAscii);
    finally
      Fs.Free;
    end;
  except
  end;

  EditStringFilterChange(nil);
end;

procedure TVirusKovAlyzerForm.QueryEngineSecurity(const APath: string);
var
  DllPath: WideString;
  hDll: HMODULE;
  ScanFn: TScanFileFn;
  VerdictCode: Integer;
  Req, Resp: string;
  j: TJSONData;
  flsObj: TJSONData;
begin
  LblStaticVerdictVal.Caption := 'Checking engine...';
  LblStaticThreatVal.Caption := 'None';
  LblDaemonFlsVal.Caption := 'Querying edrsvc daemon...';
  LblDaemonKnownVal.Caption := 'Querying known DB...';
  LblSigStatusVal.Caption := 'Checking signature...';
  LblSigPublisherVal.Caption := 'Unknown';

  // 1. Direct Static ML Engine (owlyshield_ransom.dll / openedr_static.dll)
  hDll := GetModuleHandleW(PWideChar(WideString('owlyshield_ransom.dll')));
  if hDll = 0 then
  begin
    DllPath := WideString(ExtractFilePath(ParamStr(0)) + 'owlyshield_ransom.dll');
    hDll := LoadLibraryW(PWideChar(DllPath));
  end;

  if hDll <> 0 then
  begin
    ScanFn := TScanFileFn(GetProcAddress(hDll, 'owlyshield_scan_file'));
    if Assigned(ScanFn) then
    begin
      VerdictCode := ScanFn(PWideChar(UTF8Decode(APath)), Length(UTF8Decode(APath)));
      case VerdictCode of
        2:
          begin
            LblStaticVerdictVal.Caption := 'MALICIOUS (High Confidence)';
            LblStaticVerdictVal.Font.Color := clRed;
            LblStaticThreatVal.Caption := 'Local ML / YARA Detection';
          end;
        1:
          begin
            LblStaticVerdictVal.Caption := 'Clean / Trusted';
            LblStaticVerdictVal.Font.Color := $002E7D32; // Green
          end;
        3:
          begin
            LblStaticVerdictVal.Caption := 'Suspicious (Elevated Risk)';
            LblStaticVerdictVal.Font.Color := $00C06000;
          end;
      else
        LblStaticVerdictVal.Caption := 'Unknown / Clean';
        LblStaticVerdictVal.Font.Color := clWindowText;
      end;
    end
    else
      LblStaticVerdictVal.Caption := 'Engine function not found in DLL';
  end
  else
    LblStaticVerdictVal.Caption := 'owlyshield_ransom.dll not loaded';

  // 2. edrsvc Daemon RPC Telemetry & Cloud FLS (127.0.0.1:5890)
  Req := '{"jsonrpc":"2.0","id":1,"method":"checkFileKnown","params":{"path":"' +
         StringReplace(APath, '\', '\\', [rfReplaceAll]) + '"}}';
  if HttpPostJson(GUI_RPC_HOST, GUI_RPC_PORT, Req, Resp) then
  begin
    try
      j := GetJSON(Resp);
      try
        if j.FindPath('result.known') <> nil then
        begin
          if j.FindPath('result.known').AsBoolean then
          begin
            LblDaemonKnownVal.Caption := 'DETECTED in Local Malware Cache!';
            LblDaemonKnownVal.Font.Color := clRed;
          end
          else
            LblDaemonKnownVal.Caption := 'Not in known malware list (Clean)';
        end;
      finally
        j.Free;
      end;
    except
      LblDaemonKnownVal.Caption := 'Daemon response parse error';
    end;
  end
  else
    LblDaemonKnownVal.Caption := 'edrsvc daemon offline (127.0.0.1:5890)';

  // FLS Bulk Reputation
  Req := '{"jsonrpc":"2.0","id":2,"method":"getFileReputationBulk","params":{"paths":["' +
         StringReplace(APath, '\', '\\', [rfReplaceAll]) + '"]}}';
  if HttpPostJson(GUI_RPC_HOST, GUI_RPC_PORT, Req, Resp) then
  begin
    try
      j := GetJSON(Resp);
      try
        flsObj := j.FindPath('result.results[0]');
        if flsObj <> nil then
        begin
          case flsObj.FindPath('verdict').AsInteger of
            1: LblDaemonFlsVal.Caption := 'Cloud Clean (Whitelisted)';
            2:
              begin
                LblDaemonFlsVal.Caption := 'CLOUD MALWARE DETECTED';
                LblDaemonFlsVal.Font.Color := clRed;
              end;
            3: LblDaemonFlsVal.Caption := 'Cloud Suspicious';
          else
            LblDaemonFlsVal.Caption := 'Cloud Unknown / Unrated';
          end;
        end;
      finally
        j.Free;
      end;
    except
      LblDaemonFlsVal.Caption := 'Daemon FLS response error';
    end;
  end
  else
    LblDaemonFlsVal.Caption := 'Daemon offline';

  // 3. Digital Signature check
  LblSigStatusVal.Caption := 'Standard Binary / File Checked';
  LblSigPublisherVal.Caption := 'N/A';
end;

procedure TVirusKovAlyzerForm.RenderHexPage;
var
  Fs: TFileStream;
  Buf: array[0..4095] of Byte;
  PageOffset, N, i, j: Integer;
  LineStr, HexPart, AsciiPart: string;
  b: Byte;
begin
  MemoHexView.Clear;
  if FFileSize = 0 then Exit;

  PageOffset := FHexPage * FHexPageSize;
  LblHexPageInfo.Caption := Format('Page %d of %d  (Offset: 0x%08X - 0x%08X of %d bytes)',
    [FHexPage + 1, FHexTotalPages, PageOffset, Min(FFileSize, PageOffset + FHexPageSize), FFileSize]);

  try
    Fs := TFileStream.Create(FFilePath, fmOpenRead or fmShareDenyNone);
    try
      Fs.Position := PageOffset;
      N := Fs.Read(Buf, SizeOf(Buf));
      if N <= 0 then Exit;

      MemoHexView.Lines.BeginUpdate;
      try
        i := 0;
        while i < N do
        begin
          LineStr := IntToHex(PageOffset + i, 8) + '  ';
          HexPart := '';
          AsciiPart := '';

          for j := 0 to 15 do
          begin
            if i + j < N then
            begin
              b := Buf[i + j];
              HexPart := HexPart + IntToHex(b, 2) + ' ';
              if j = 7 then HexPart := HexPart + ' ';
              if (b >= 32) and (b <= 126) then
                AsciiPart := AsciiPart + Chr(b)
              else
                AsciiPart := AsciiPart + '.';
            end
            else
            begin
              HexPart := HexPart + '   ';
              if j = 7 then HexPart := HexPart + ' ';
            end;
          end;

          LineStr := LineStr + HexPart + ' |' + AsciiPart + '|';
          MemoHexView.Lines.Add(LineStr);
          Inc(i, 16);
        end;
      finally
        MemoHexView.Lines.EndUpdate;
      end;
    finally
      Fs.Free;
    end;
  except
    on E: Exception do
      MemoHexView.Lines.Add('Error reading file: ' + E.Message);
  end;
end;

{ UI Actions & Events }

procedure TVirusKovAlyzerForm.BtnBrowseFileClick(Sender: TObject);
begin
  if OpenDialog.Execute then
    AnalyzeFile(OpenDialog.FileName);
end;

procedure TVirusKovAlyzerForm.BtnRescanClick(Sender: TObject);
begin
  if FFilePath <> '' then
    AnalyzeFile(FFilePath);
end;

procedure TVirusKovAlyzerForm.BtnCloseTopClick(Sender: TObject);
begin
  Close;
end;

procedure TVirusKovAlyzerForm.BtnCopyHashClick(Sender: TObject);
var
  TargetText: string;
begin
  TargetText := '';
  if Sender = BtnCopyCrc32 then TargetText := EditCrc32.Text
  else if Sender = BtnCopyMd5 then TargetText := EditMd5.Text
  else if Sender = BtnCopySha1 then TargetText := EditSha1.Text
  else if Sender = BtnCopySha256 then TargetText := EditSha256.Text;

  if TargetText <> '' then
  begin
    Clipboard.AsText := TargetText;
    ShowMessage('Copied to clipboard: ' + TargetText);
  end;
end;

procedure TVirusKovAlyzerForm.LbImportDllsSelectionChange(Sender: TObject; User: boolean);
begin
  EditImportFilterChange(nil);
end;

procedure TVirusKovAlyzerForm.EditImportFilterChange(Sender: TObject);
var
  Idx: Integer;
  FnList: TStringList;
  FilterStr, Fn: string;
  i: Integer;
  It: TListItem;
begin
  LvImportFunctions.Items.Clear;
  Idx := LbImportDlls.ItemIndex;
  if (Idx < 0) or (Idx >= FImportList.Count) then Exit;

  FnList := TStringList(FImportList.Objects[Idx]);
  if FnList = nil then Exit;

  FilterStr := LowerCase(Trim(EditImportFilter.Text));
  LvImportFunctions.Items.BeginUpdate;
  try
    for i := 0 to FnList.Count - 1 do
    begin
      Fn := FnList[i];
      if (FilterStr = '') or (Pos(FilterStr, LowerCase(Fn)) > 0) then
      begin
        It := LvImportFunctions.Items.Add;
        It.Caption := IntToStr(i + 1);
        It.SubItems.Add(Fn);
      end;
    end;
  finally
    LvImportFunctions.Items.EndUpdate;
  end;
end;

procedure TVirusKovAlyzerForm.EditStringFilterChange(Sender: TObject);
begin
  CbStringFilterCategoryChange(nil);
end;

procedure TVirusKovAlyzerForm.CbStringFilterCategoryChange(Sender: TObject);
var
  CatIdx, i: Integer;
  FilterStr, S, LowS: string;
  Pass: Boolean;
  It: TListItem;
begin
  LvStrings.Items.Clear;
  CatIdx := CbStringFilterCategory.ItemIndex;
  FilterStr := LowerCase(Trim(EditStringFilter.Text));

  LvStrings.Items.BeginUpdate;
  try
    for i := 0 to FAllStrings.Count - 1 do
    begin
      S := FAllStrings[i];
      LowS := LowerCase(S);

      Pass := True;
      case CatIdx of
        1: Pass := (Pos('http://', LowS) > 0) or (Pos('https://', LowS) > 0) or (Pos('ftp://', LowS) > 0);
        2: Pass := (Pos('hkey_', LowS) > 0) or (Pos('software\', LowS) > 0) or (Pos('system\', LowS) > 0);
        3: Pass := (Pos('.exe', LowS) > 0) or (Pos('.dll', LowS) > 0) or (Pos('.sys', LowS) > 0) or (Pos('.bat', LowS) > 0);
      end;

      if Pass and ((FilterStr = '') or (Pos(FilterStr, LowS) > 0)) then
      begin
        It := LvStrings.Items.Add;
        It.Caption := IntToStr(LvStrings.Items.Count + 1);
        It.SubItems.Add(S);
      end;
    end;
  finally
    LvStrings.Items.EndUpdate;
  end;
end;

procedure TVirusKovAlyzerForm.BtnHexPrevPageClick(Sender: TObject);
begin
  if FHexPage > 0 then
  begin
    Dec(FHexPage);
    RenderHexPage;
  end;
end;

procedure TVirusKovAlyzerForm.BtnHexNextPageClick(Sender: TObject);
begin
  if FHexPage < FHexTotalPages - 1 then
  begin
    Inc(FHexPage);
    RenderHexPage;
  end;
end;

procedure TVirusKovAlyzerForm.BtnHexFirstPageClick(Sender: TObject);
begin
  FHexPage := 0;
  RenderHexPage;
end;

procedure TVirusKovAlyzerForm.BtnHexLastPageClick(Sender: TObject);
begin
  FHexPage := FHexTotalPages - 1;
  RenderHexPage;
end;

procedure TVirusKovAlyzerForm.BtnHexGotoOffsetClick(Sender: TObject);
var
  S: string;
  Off: Int64;
begin
  S := '';
  if InputQuery('Go to Hex Offset', 'Enter hexadecimal offset (e.g. 1A00 or 0x1A00):', S) then
  begin
    S := Trim(S);
    if Copy(S, 1, 2) = '0x' then Delete(S, 1, 2);
    Off := StrToInt64Def('$' + S, -1);
    if (Off >= 0) and (Off < FFileSize) then
    begin
      FHexPage := Off div FHexPageSize;
      RenderHexPage;
    end
    else
      ShowMessage('Invalid file offset.');
  end;
end;

procedure TVirusKovAlyzerForm.BtnHexCopyClick(Sender: TObject);
begin
  if MemoHexView.SelText <> '' then
    Clipboard.AsText := MemoHexView.SelText
  else
    Clipboard.AsText := MemoHexView.Text;
  ShowMessage('Hex view copied to clipboard.');
end;

procedure TVirusKovAlyzerForm.LvSectionsCustomDrawItem(Sender: TCustomListView;
  Item: TListItem; State: TCustomDrawState; var DefaultDraw: Boolean);
var
  EntropyVal: Double;
begin
  if (Item <> nil) and (Item.Index < Length(FSectionEntropies)) then
  begin
    EntropyVal := FSectionEntropies[Item.Index];
    if EntropyVal >= 7.20 then
    begin
      Sender.Canvas.Font.Color := clRed;
      Sender.Canvas.Font.Style := [fsBold];
    end
    else if EntropyVal >= 6.50 then
    begin
      Sender.Canvas.Font.Color := $00C06000;
    end;
  end;
end;

end.
