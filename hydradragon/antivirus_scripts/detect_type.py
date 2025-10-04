from hydra_logger import logger

import string
import re
import struct
from typing import Union, Optional, Tuple
import pefile
import chardet
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
import macholib.MachO
from androguard.misc import APK
from androguard.core.apk import APK

def is_go_garble_from_output(die_output):
    """
    Check if the DIE output indicates a Go garbled file.
    A file is considered garble if the output contains:
      - "Compiler: Go(unknown)"
    """
    if die_output and ("Compiler: Go(unknown)" in die_output):
        logger.info("DIE output indicates a garbled Go file.")
        return True
    return False

def is_pyc_file_from_output(die_output):
    """
    Check if the DIE output indicates a Python compiled module (.pyc file).
    It looks for markers that suggest it's a Python compiled module.
    """
    if die_output and "Python Compiled Module" in die_output:
        logger.info("DIE output indicates a Python compiled module.")
        return True
    return False

def is_pyarmor_archive_from_output(data: bytes) -> bool:
    """
    Returns True if the file content is a PyArmor-protected .pyc file, False otherwise.
    """
    return data.startswith(b'PY00') and b'__pyarmor__' in data

def is_themida_from_output(die_output):
    """
    Check if the DIE output indicates Themida/WinLicense protection.
    Matches 'Protector: Themida/Winlicense (2.XX)' or '(3.XX)' in PE32/PE64 binaries.
    Case-sensitive; does NOT use startswith.
    """
    if not die_output:
        return None

    s = die_output.strip()

    if "Protector: Themida/Winlicense (2.XX)" in s or \
       "Protector: Themida/Winlicense (3.XX)" in s:

        if "PE32" in s:
            logger.info("DIE output indicates PE32 protected with Themida/WinLicense.")
            return "PE32 Themida"
        if "PE64" in s:
            logger.info("DIE output indicates PE64 protected with Themida/WinLicense.")
            return "PE64 Themida"

    return None

def is_vm_protect_from_output(die_output):
    """
    Check if the DIE output indicates VMProtect protection for PE32 or PE64.
    Case-sensitive; does NOT use startswith. Returns True only if the output
    contains 'Protector: VMProtect' AND either 'PE32' or 'PE64' anywhere.
    Otherwise returns False.
    """
    if not die_output:
        return False

    s = die_output.strip()

    # must contain the exact protector token
    if "Protector: VMProtect" not in s:
        return False

    # must contain one of the PE markers somewhere in the output
    if "PE32" in s:
        logger.info("DIE output indicates PE32 protected with VMProtect.")
        return True
    if "PE64" in s:
        logger.info("DIE output indicates PE64 protected with VMProtect.")
        return True

    return False

def is_pe_file_from_output(die_output: str, file_path: str) -> Union[bool, str]:
    """
    Checks if DIE output or pefile validation indicates a PE (Portable Executable) file.

    Args:
        die_output: The output string from DIE (Detect It Easy).
        file_path: The path to the suspected PE file.

    Returns:
        True if the file appears to be a PE file,
        "Broken Executable" if DIE indicates PE but pefile fails to parse it,
        False otherwise.
    """
    # Check DIE output first (case-sensitive, no startswith)
    if die_output:
        s = die_output.strip()
        if "PE32" in s or "PE64" in s:
            logger.info("DIE output indicates a PE file.")

            # Cross-validate using pefile
            try:
                pefile.PE(file_path, fast_load=True)
                logger.info("pefile successfully parsed the file as PE.")
                return True
            except pefile.PEFormatError:
                logger.error("DIE said PE, but pefile couldn't parse it. Possibly corrupted.")
                return "Broken Executable"

    # If DIE doesn't indicate PE (or die_output is empty), try pefile directly
    try:
        pefile.PE(file_path, fast_load=True)
        logger.info("pefile detected a PE file even though DIE did not.")
        return True
    except pefile.PEFormatError:
        return False

def is_cx_freeze_file_from_output(die_output):
    """Checks if DIE output indicates a cx_Freeze file."""
    if die_output and ("Packer: cx_Freeze(5.x+)" in die_output):
        logger.info("DIE output indicates a cx_Freeze file.")
        return True
    return False

def is_advanced_installer_file_from_output(die_output):
    """Checks if DIE output indicates a Advanced Installer file."""
    if die_output and ("Advanced Installer" in die_output):
        logger.info("DIE output indicates a Advanced Installer file.")
        return True
    return False

def is_autoit_file_from_output(die_output):
    """Checks if DIE output indicates a AutoIt file."""
    if die_output and ("AutoIt" in die_output):
        logger.info("DIE output indicates a AutoIt file.")
        return True
    return False

def is_jsc_from_output(die_output: str) -> Optional[str]:
    """
    Detect JavaScript Compiled/Bytenode (.JSC) files from DIE output.

    Requirements (case-sensitive):
      - die_output must start with "Binary"
      - must contain "Language: JavaScript"
      - must contain "Format: JavaScript Compiled/Bytenode" or ".JSC"

    Tries to extract:
      - a Bytenode/JSC version like v9.4.146.24 (looks for "v\\d+\\.\\d+\\.\\d+\\.\\d+")
      - V8 Version occurrences like "V8 Version 9.4.146.24"
      - architecture: "x86" or "x64" (looks for tokens near the version or anywhere in output)

    Returns:
      - e.g. "JSC v9.4.146.24 x64"  (best case: version + arch)
      - e.g. "JSC (unknown version) x86" (if arch found but no explicit version)
      - "JSC (unknown version)" (if format & language matched but no arch/version)
      - None if detection requirements are not satisfied.
    """
    if not die_output:
        return None

    s = die_output.strip()

    # require startswith Binary (case-sensitive)
    if not s.startswith("Binary"):
        return None

    # require both tokens present (case-sensitive)
    if "Language: JavaScript" not in s:
        return None
    if "Format: JavaScript Compiled/Bytenode" not in s and ".JSC" not in s:
        return None

    # Attempt to find a explicit bytenode-style version: (v9.4.146.24) or v9.4.146.24
    version = None
    # look for "(vX.Y.Z.W" or "vX.Y.Z.W" possibly followed by " x64"/" x86"
    m = re.search(r'\(v(\d+\.\d+\.\d+\.\d+)\s*(x86|x64)?\)', s)
    if m:
        version = m.group(1)
        # arch_in_paren = m.group(2)
    else:
        m = re.search(r'\bv(\d+\.\d+\.\d+\.\d+)\b', s)
        if m:
            version = m.group(1)
        # also check "V8 Version" occurrences
        if not version:
            m2 = re.search(r'V8 Version\s+(\d+\.\d+\.\d+\.\d+)', s)
            if m2:
                version = m2.group(1)

    # Determine architecture: try to find x64/x86 near version first, else anywhere
    arch = None
    if version:
        # search for "version ... x64" on the same line or within small window
        # find position of version and scan nearby characters
        pos = s.find(version)
        if pos != -1:
            window = s[max(0, pos - 60): pos + 60]
            if "x64" in window:
                arch = "x64"
            elif "x86" in window:
                arch = "x86"

    # fallback: look anywhere in the output for common arch tokens
    if not arch:
        if " x64" in s or "x64)" in s or " x64 " in s:
            arch = "x64"
        elif " x86" in s or "x86)" in s or " x86 " in s:
            arch = "x86"

    # Build return string
    if version and arch:
        logger.info(f"DIE output indicates JavaScript Compiled/Bytenode (.JSC): v{version} {arch}.")
        return f"JSC v{version} {arch}"
    if version:
        logger.info(f"DIE output indicates JavaScript Compiled/Bytenode (.JSC): v{version} (arch unknown).")
        return f"JSC v{version} (arch unknown)"
    if arch:
        logger.info(f"DIE output indicates JavaScript Compiled/Bytenode (.JSC) {arch} (version unknown).")
        return f"JSC (unknown version) {arch}"

    logger.info("DIE output indicates JavaScript Compiled/Bytenode (.JSC) but no version/arch could be determined.")
    return "JSC (unknown version)"

def is_npm_from_output(die_output):
    """
    Case-sensitive check: return True if die_output contains the exact tokens
    'Packer: npm', 'Language: JavaScript', and either 'PE32' or 'PE64' anywhere.
    Otherwise return False.
    """
    if not die_output:
        return False

    s = die_output.strip()

    if "Packer: npm" in s and "Language: JavaScript" in s and ("PE32" in s or "PE64" in s):
        pe = "PE32" if "PE32" in s else "PE64"
        logger.info(f"DIE output indicates {pe} packed with npm and Language: JavaScript.")
        return True

    return False

def is_asar_archive_from_output(die_output):
    """
    Checks if the first two lines of DIE output indicate an Asar Archive (Electron).
    Ignores all other lines and warnings.
    """
    if not die_output:
        return False

    # Split lines and strip whitespace
    lines = [line.strip() for line in die_output.splitlines() if line.strip()]

    # Only consider the first two lines
    first_two = lines[:2]

    expected = ["Binary", "Archive: Asar Archive (Electron)"]

    if first_two == expected:
        logger.info("DIE output indicates an Asar Archive (Electron).")
        return True

    return False

def is_installshield_file_from_output(die_output):
    """Checks if DIE output indicates a Install Shield file."""
    if die_output and ("InstallShield" in die_output):
        logger.info("DIE output indicates a Install Shield file.")
        return True
    return False

def is_nsis_from_output(die_output: str) -> bool:
    """Checks if DIE output indicates an NSIS installer file."""
    if not die_output:
        logger.info("DIE output is empty or None.")
        return False

    # Look for NSIS installer signatures in the output
    indicators = [
        "Nullsoft Scriptable Install System",  # e.g. Installer: Nullsoft Scriptable Install System(2.46-Unicode)[lzma]
        "Data: NSIS data"
    ]

    if any(indicator in die_output for indicator in indicators):
        logger.info("DIE output indicates an NSIS installer.")
        return True

    return False

def is_elf_file_from_output(die_output: str, file_path: str) -> bool:
    """
    Checks if DIE output or ELF validation indicates an ELF file.

    Args:
        die_output: The output string from DIE (Detect It Easy).
        file_path: The path to the suspected ELF file.

    Returns:
        True if the file appears to be an ELF file,
        "Broken Executable" if DIE detects ELF but parsing fails,
        False otherwise.
    """
    # Check DIE output first
    if die_output and (die_output.startswith("ELF32") or die_output.startswith("ELF64")):
        logger.info("DIE output indicates an ELF file.")

        # Cross-validate using pyelftools
        try:
            with open(file_path, 'rb') as f:
                elf_file = ELFFile(f)
                # Basic validation - check if we can read the header
                header = elf_file.header
                logger.info(f"ELF file successfully parsed. Architecture: {header['e_machine']}")
                return True
        except (ELFError, IOError, ValueError) as e:
            logger.error(f"DIE said ELF, but pyelftools couldn't parse it: {e}. Possibly corrupted.")
            return "Broken Executable"

    # If DIE doesn't say ELF, try pyelftools directly
    try:
        with open(file_path, 'rb') as f:
            elf_file = ELFFile(f)
            header = elf_file.header
            logger.info("pyelftools detected an ELF file even though DIE did not.")
            return True
    except (ELFError, IOError, ValueError):
        return False

def is_apk_file_from_output(
    die_output: str,
    file_path: str
) -> Union[bool, str, Tuple[object, list, object]]:
    """
    Determines whether the given file is an APK by checking DIE's detection result,
    then validating it via Androguard (AnalyzeAPK).

    Returns:
        (a, d, dx)     - if analysis succeeds
        True           - if only APK validity check succeeds
        "Broken APK"   - if DIE claimed APK but Androguard failed
        False          - otherwise
    """

    if die_output:
        logger.info(f"DIE output: {die_output.strip()}")

    if not die_output or "APK" not in die_output.upper():
        return False

    try:
        a, d, dx = AnalyzeAPK(file_path)

        if not a:
            logger.error("AnalyzeAPK returned no APK object.")
            return "Broken APK"

        if a.is_valid_APK():
            logger.info("Androguard confirms this is a valid APK.")
            # Return full details (APK object, list of DEX objects, Analysis object)
            return a, d, dx
        else:
            logger.warning("AnalyzeAPK parsed but validity failed.")
            return "Broken APK"

    except Exception as e:
        logger.error(f"AnalyzeAPK crashed: {e}")

        # Fallback: try a lighter APK parse
        try:
            apk = APK(file_path)
            if apk.is_valid_APK():
                logger.info("Fallback: APK structure looks valid.")
                return True
        except Exception as inner_e:
            logger.error(f"Fallback APK parse also failed: {inner_e}")

        return "Broken APK"

def is_enigma1_virtual_box(die_output):
    """
    Checks if DIE output indicates the Enigma Virutal Box.
    Returns True if 'Protector: Enigma' is found, else False.
    """
    if die_output and ".enigma1" in die_output:
        logger.info("DIE output indicates Protector: Enigma.")
        return True

    return False

def is_macho_file_from_output(die_output: str, file_path: str) -> bool:
    """
    Checks if DIE output or macholib validation indicates a Mach-O file.

    Args:
        die_output: The output string from DIE (Detect It Easy).
        file_path: The path to the suspected Mach-O file.

    Returns:
        True if the file appears to be a Mach-O file,
        "Broken Executable" if DIE detects Mach-O but parsing fails,
        False otherwise.
    """
    # Check DIE output first
    if die_output and (die_output.startswith("Mach-O")):
        logger.info("DIE output indicates a Mach-O file.")

        # Cross-validate using macholib
        try:
            macho = macholib.MachO.MachO(file_path)
            # Basic validation - check if we can access the headers
            for header in macho.headers:
                logger.info(f"Mach-O file successfully parsed. CPU type: {header.header.cputype}")
            return True
        except (IOError, ValueError, struct.error, IndexError, Exception) as e:
            logger.error(f"DIE said Mach-O, but macholib couldn't parse it: {e}. Possibly corrupted.")
            return "Broken Executable"

    # If DIE doesn't say Mach-O, try macholib directly
    try:
        macho = macholib.MachO.MachO(file_path)
        # Verify we can read at least one header
        headers = list(macho.headers)
        if headers:
            logger.info("macholib detected a Mach-O file even though DIE did not.")
            return True
        else:
            logger.debug("macholib found no valid headers in the file.")
            return False
    except (IOError, ValueError, struct.error, IndexError, Exception):
        return False

def is_dotnet_file_from_output(die_output):
    """
    Checks whether the DIE output indicates a .NET executable file.

    Returns:
      - False
        if "C++" appears anywhere in the output.
      - "Already Deobfuscated"
        if "Tool: de4dot[deobfuscated]" is found.
      - "Protector: Obfuscar" or "Protector: Obfuscar(<version>)"
        if it's protected with Obfuscar.
      - "Protector: ConfuserEx" or "Protector: ConfuserEx(<version>)"
        if it's protected with ConfuserEx.
      - "Protector: .NET Reactor" or "Protector: .NET Reactor(<version>)"
        if it's protected with .NET Reactor.
      - "Protector: <Name>" or "Protector: <Name>(<version>)"
        for any other Protector marker (full line captured).
      - "Probably No Protector"
        if it's a .NET file and no protector is detected.
      - None
        if none of these markers are found.
    """
    try:
        if not die_output:
            logger.info("Empty DIE output; no .NET markers found.")
            return None

        # 0) If it contains a C++ indicator, treat as non-.NET and return False
        if "C++" in die_output:
            logger.info("DIE output indicates native C++ with .NET.")
            return False

        # 1) Check if already deobfuscated by de4dot
        if "Tool: de4dot[deobfuscated]" in die_output:
            logger.info("DIE output indicates file was already deobfuscated by de4dot.")
            return "Already Deobfuscated"

        # 2) Specific Obfuscar protector
        obfuscar_match = re.search(r'Protector:\s*Obfuscar(?:\(([^)]+)\))?', die_output)
        if obfuscar_match:
            version = obfuscar_match.group(1)
            result = f"Protector: Obfuscar({version})" if version else "Protector: Obfuscar"
            logger.info(f"DIE output indicates a .NET assembly protected with {result}.")
            return result

        # 3) Specific ConfuserEx protector
        confuser_match = re.search(r'Protector:\s*ConfuserEx(?:\(([^)]+)\))?', die_output, re.IGNORECASE)
        if confuser_match:
            version = confuser_match.group(1)
            result = f"Protector: ConfuserEx({version})" if version else "Protector: ConfuserEx"
            logger.info(f"DIE output indicates a .NET assembly protected with {result}.")
            return result

        # 4) Specific .NET Reactor protector (version 6.X only)
        reactor_match = re.search(r'Protector:\s*\.NET\s*Reactor\(6\.\d+\)', die_output, re.IGNORECASE)
        if reactor_match:
            version = reactor_match.group(0).split('(')[1].rstrip(')')
            result = f"Protector: .NET Reactor({version})"
            logger.info(f"DIE output indicates a .NET assembly protected with {result}.")
            return result

        # 5) Generic Protector marker - capture the full line
        line_match = re.search(r'^Protector:.*$', die_output, re.MULTILINE)
        if line_match:
            marker = line_match.group(0).strip()
            logger.info(f"DIE output indicates .NET assembly requiring de4dot: {marker}.")
            return marker

        # 6) .NET runtime indication (only if no protector found)
        if ".NET" in die_output:
            logger.info("DIE output indicates a .NET executable without protection; we'll still process it with de4dot.")
            return "Probably No Protector"

        # 7) Nothing .NET/protector-related found
        return None

    except re.error as e:
        logger.error(f"Regular expression error in is_dotnet_file_from_output: {e}")
        return None
    except AttributeError as e:
        logger.error(f"Attribute error in is_dotnet_file_from_output (possibly invalid die_output): {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in is_dotnet_file_from_output: {e}")
        return None

def is_file_fully_unknown(die_output: str) -> bool:
    """
    Determines whether DIE output indicates an unrecognized binary file,
    ignoring any trailing error messages or extra lines.

    Returns True if the first two non-empty, whitespace-stripped lines are:
        Binary
        Unknown: Unknown
    """
    if not die_output:
        logger.info("No DIE output provided.")
        return False

    # Normalize: split into lines, strip whitespace, drop empty lines
    lines = [line.strip() for line in die_output.splitlines() if line.strip()]

    # We only care about the first two markers; ignore anything after.
    if len(lines) >= 2 and lines[0] == "Binary" and lines[1] == "Unknown: Unknown":
        logger.info("DIE output indicates an unknown file (ignoring extra errors).")
        return True
    else:
        return False

def is_packed_from_output(die_output):
    """
    Check if the DIE output indicates a packed/protected binary.
    Case-sensitive checks; does NOT use startswith. Based on YARA-like signatures
    (UPX, ASPack, FSG, PECompact, Upack, PEtite, MEW, YZPack, MPRESS) and a generic
    "Packer:" indicator.

    Returns:
        - "PE64 Packed (<PACKER>)" or "PE32 Packed (<PACKER>)" if a PE marker and a packer are found,
        - "Packed (<PACKER>)" if a packer is found but no PE marker,
        - None if nothing matched or die_output is empty.
    """
    if not die_output:
        return None

    s = die_output.strip()

    # Specific packer signatures based on your YARA rules only
    packer_signatures = {
        # UPX variants
        'UPX': ['UPX', 'UPX0', 'UPX1', 'UPX2', 'UPX!', 'upX'],

        # ASPack
        'ASPACK': ['.aspack', '.adata'],

        # FSG (Fast Small Good)
        'FSG': ['FSG'],

        # PECompact
        'PECOMPACT': ['PECompact', 'PECompact2'],

        # Upack
        'UPACK': ['Upack'],

        # PEtite
        'PETITE': ['.petite', 'petite'],

        # MEW (Magic Executable Wizard)
        'MEW': ['MEW'],

        # YZPack
        'YZPACK': ['.yzpack', '.yzpack2'],

        # MPRESS
        'MPRESS': ['.MPRESS1', '.MPRESS2']
    }

    detected_packer = None

    # Case-sensitive "Packer:" indicator first
    if 'Packer:' in s:
        detected_packer = "GENERIC"
    else:
        # Check for specific packer signatures from your YARA rules
        for packer_name, signatures in packer_signatures.items():
            for signature in signatures:
                if signature in s:
                    detected_packer = packer_name
                    break
            if detected_packer:
                break

    # Return result based on presence of PE markers anywhere (no startswith)
    if detected_packer:
        if "PE64" in s:
            logger.info(f"DIE output indicates PE64 packed/protected binary: {detected_packer}")
            return f"PE64 Packed ({detected_packer})"
        if "PE32" in s:
            logger.info(f"DIE output indicates PE32 packed/protected binary: {detected_packer}")
            return f"PE32 Packed ({detected_packer})"

        logger.info(f"DIE output indicates packed/protected binary: {detected_packer}")
        return f"Packed ({detected_packer})"

    return None

def is_packer_upx_output(die_output):
    """
    Checks if DIE output indicates that the file is packed with UPX.
    Looks for the marker 'Packer: UPX' (optionally with version/modifier).
    """
    if die_output and re.search(r"Packer:\s*UPX\b", die_output):
        logger.info("DIE output indicates UPX packer.")
        return True

    return False

def is_jar_file_from_output(die_output):
    """Checks if DIE output indicates a JAR file (Java archive)."""
    if die_output and "Virtual machine: JVM" in die_output:
        logger.info("DIE output indicates a JAR file.")
        return True
    return False

def is_java_class_from_output(die_output):
    """
    Checks if the DIE output indicates a Java class file.
    It does this by looking for 'Format: Java Class File' in the output.
    """
    if die_output and "Format: Java Class " in die_output:
        logger.info("DIE output indicates a Java class file.")
        return True
    return False

def is_plain_text(data: bytes,
                  null_byte_threshold: float = 0.01,
                  printable_threshold: float = 0.95) -> bool:
    """
    Heuristic: data is plain text if
      1. It contains very few null bytes,
      2. A high fraction of bytes are printable or common whitespace,
      3. And it decodes cleanly in some text encoding (e.g. UTF-8, Latin-1).

    :param data:       raw file bytes
    :param null_byte_threshold:
                       max fraction of bytes that can be zero (0x00)
    :param printable_threshold:
                       min fraction of bytes in printable + whitespace set
    """
    if not data:
        return True

    # 1) Null byte check
    nulls = data.count(0)
    if nulls / len(data) > null_byte_threshold:
        return False

    # 2) Printable char check
    printable = set(bytes(string.printable, 'ascii'))
    count_printable = sum(b in printable for b in data)
    if count_printable / len(data) < printable_threshold:
        return False

    # 3) Try a text decoding
    #    Use chardet to guess encoding
    guess = chardet.detect(data)
    enc = guess.get('encoding') or 'utf-8'
    try:
        data.decode(enc)
        return True
    except (UnicodeDecodeError, LookupError):
        return False

def is_plain_text_file_from_output(die_output):
    """
    Checks if the DIE output does indicate plain text, suggesting it is plain text data.
    """
    if die_output and "Format: plain text" in die_output.lower():
        logger.info("DIE output does not contain plain text; identified as non-plain text data.")
        return True
    return False

def is_7z_file_from_output(die_output: str) -> bool:
    """
    Checks if DIE output indicates a 7-Zip archive.
    Expects the raw stdout (or equivalent) from a Detect It Easy run.
    """
    if die_output and "Archive: 7-Zip" in die_output:
        logger.info("DIE output indicates a 7z archive.")
        return True

    return False

def is_pyinstaller_archive_from_output(die_output):
    """
    Check if the DIE output indicates a PyInstaller archive.
    A file is considered a PyInstaller archive if the output contains:
      - "Packer: PyInstaller"
    """
    if die_output and "Packer: PyInstaller" in die_output:
        logger.info("DIE output indicates a PyInstaller archive.")
        return True

    return False

def is_microsoft_compound_file_from_output(die_output: str) -> bool:
    """
    Check if DIE output indicates a Microsoft Compound File (OLE2).

    Args:
        die_output: Output from DIE (Detect It Easy) tool

    Returns:
        True if the file is an OLE2/Microsoft Office file
    """
    ole_indicators = [
        'Microsoft Compound File',
        'OLE',
        'MS Office',
        'Word',
        'Excel',
        'PowerPoint',
        '.doc',
        '.xls',
        '.ppt',
        'Composite Document File'
    ]
    return any(indicator.lower() in die_output.lower() for indicator in ole_indicators)

def is_nuitka_file_from_output(die_output):
    """
    Check if the DIE output indicates a Nuitka executable.
    Returns:
      - "Nuitka OneFile" if the DIE output contains "Packer: Nuitka[OneFile]"
      - "Nuitka" if the DIE output contains "Packer: Nuitka"
      - None otherwise.
    """
    if die_output is None:
        logger.error("No DIE output available for Nuitka check.")
        return None

    if "Packer: Nuitka[OneFile]" in die_output:
        logger.info("DIE output indicates a Nuitka OneFile executable.")
        return "Nuitka OneFile"
    elif "Packer: Nuitka" in die_output:
        logger.info("DIE output indicates a Nuitka executable.")
        return "Nuitka"
    else:
        return None

def is_compiled_autohotkey_file_from_output(die_output):
    """
    Check if the DIE output indicates a compiled AutoHotkey executable.

    A file is considered a compiled AutoHotkey binary if the output contains:
      - "Format: Compiled AutoHotKey"
    Optionally, the version string in parentheses may also be present,
    e.g. "Format: Compiled AutoHotKey(1.1.00.00)".
    """
    if not die_output:
        return False

    if "Format: Compiled AutoHotKey" in die_output:
        logger.info("DIE output indicates a compiled AutoHotkey executable.")
        return True

    return False

def is_inno_setup_file_from_output(die_output):
    """
    Check if the DIE output indicates an Inno Setup installer.
    A file is considered an Inno Setup installer if the output contains both:
      - "Data: Inno Setup Installer data"
      - "Installer: Inno Setup Module"
    """
    if die_output and \
       "Data: Inno Setup Installer data" in die_output and \
       "Installer: Inno Setup Module" in die_output:
        logger.info("DIE output indicates an Inno Setup installer.")
        return True

    return False
