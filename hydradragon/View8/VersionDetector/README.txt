Build VersionDetector.exe with MSVC maximum optimization:

cl /nologo /O2 /Ob3 /Oi /Ot /Oy /GL /GF /GS- /Gy /Gw /fp:fast /MT /DNDEBUG VersionDetector_fast.c /link /LTCG /OPT:REF /OPT:ICF /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /RELEASE /OUT:VersionDetector.exe

Test commands:

VersionDetector.exe -h 14.6.202.33
VersionDetector.exe -d b65c9b2a
VersionDetector.exe -f C:\Users\semae\OneDrive\Belgeler\main.jsc
