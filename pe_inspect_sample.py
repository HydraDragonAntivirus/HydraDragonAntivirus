import pefile
import hashlib

path = r"C:\viruskov_archive\multron_incoming\unknown\pe64\652F72976536214578A6EF848D7359495E02DB58846D15EA3A85E90EF1040DC9_python.exe"

with open(path, "rb") as f:
    data = f.read()

print("SHA256:", hashlib.sha256(data).hexdigest())
print("Size:", len(data))

pe = pefile.PE(data=data)
print("PE Machine:", hex(pe.FILE_HEADER.Machine))
print("Timestamp:", hex(pe.FILE_HEADER.TimeDateStamp))
print("Number of sections:", len(pe.sections))
for s in pe.sections:
    name = s.Name.decode('utf-8', errors='ignore').strip('\x00')
    print(f"  Section {name}: VirtualSize={hex(s.Misc_VirtualSize)}, RawSize={hex(s.SizeOfRawData)}, Entropy={s.get_entropy():.2f}")

print("\n--- Imports ---")
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('utf-8', errors='ignore')
        print(f"DLL: {dll}")
        for imp in entry.imports[:5]:
            name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"ord({imp.ordinal})"
            print(f"   {name}")

print("\n--- Version Info ---")
try:
    if hasattr(pe, 'FileInfo'):
        for v in pe.FileInfo[0]:
            if hasattr(v, 'StringTable'):
                for st in v.StringTable:
                    for k, val in st.entries.items():
                        print(f"  {k.decode('utf-8', errors='ignore')}: {val.decode('utf-8', errors='ignore')}")
except Exception as e:
    print("Version info error:", e)
