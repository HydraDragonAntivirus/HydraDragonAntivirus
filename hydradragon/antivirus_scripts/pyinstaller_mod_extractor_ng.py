"""
PyInstaller Extractor NG v1.0 (Supports pyinstaller 5.10.1, 5.10.0, 5.9.0, 5.8.0, 5.7.0, 5.6.2, 5.6.1, 5.6, 5.5, 5.4.1, 5.4, 5.3, 5.2, 5.1, 5.0.1, 5.0, 4.10, 4.9, 4.8, 4.7, 4.6, 4.5.1, 4.5, 4.4, 4.3, 4.2, 4.1, 4.0, 3.6, 3.5, 3.4, 3.3, 3.2, 3.1, 3.0, 2.1, 2.0)
Author : Extreme Coders
E-mail : extremecoders(at)hotmail(dot)com
Web    : https://0xec.blogspot.com
Url    : https://github.com/pyinstxtractor/pyinstxtractor-ng

This script extracts a pyinstaller generated executable file. 
Uses the xdis library to unmarshal code objects, hence you should
be able to decompile an executable from any Python version without
being restricted to use the same version of Python for running the
script as well.

Licensed under GNU General Public License (GPL) v3.

This script was modified by Karsten Hahn @ GDATA CyberDefense to extract a custom PyInstaller variant.

These modifications are also licensed under GPLv3+.

See article: https://samplepedia.cc/sample/8c9d9150efa35278afcb23f2af4c4babcc4dd55acd9e839bed4c04cb5a8d9c3f/81/solution/52/view/

Samples:
* 09474277051fc387a9b43f7f08a9bf4f6817c24768719b21f9f7163d9c5c8f74 
* 8c9d9150efa35278afcb23f2af4c4babcc4dd55acd9e839bed4c04cb5a8d9c3f

"""

from .hydra_logger import logger

import os
import sys
import zlib
import struct
import argparse
import re
import marshal
import pefile

from uuid import uuid4 as uniquename

from Crypto.Cipher import AES
from Crypto.Util import Counter

from xdis.unmarshal import load_code

def pycHeader2Magic(header):
    header = bytearray(header)
    magicNumber = bytearray(header[:2])
    return magicNumber[1] << 8 | magicNumber[0]

def find_pyinstaller_magic(filename):
    logger.info("[+] Testing cookie locations, this may take a bit ...")
    try:
        pe = pefile.PE(filename)
        overlay_offset = pe.get_overlay_data_start_offset()
        
        if overlay_offset is None:
            logger.info("[ERROR] No PE overlay found")
            return None
        
    except:
        logger.info("[ERROR] Could not parse as PE file")
        return None
    
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Search from the overlay start to the end of file
    for i in range(overlay_offset, len(data) - 32):
        try:
            # Try to parse as a cookie structure
            # 8 bytes magic + 4 bytes pkg_len + 4 bytes toc_offset + 4 bytes toc_len + 4 bytes pyver
            pkg_len = struct.unpack('!I', data[i+8:i+12])[0]
            toc_offset = struct.unpack('!I', data[i+12:i+16])[0]
            toc_len = struct.unpack('!I', data[i+16:i+20])[0]
            pyver = struct.unpack('!I', data[i+20:i+24])[0]
            
            # Validate the structure
            if (0 < pkg_len < len(data) and 
                0 < toc_offset < pkg_len and 
                0 < toc_len < pkg_len and
                20 <= pyver <= 400):
                # This looks like a valid cookie, extract the 8-byte magic
                magic = data[i:i+8]
                logger.info(f"[+] Found valid cookie at: 0x{i:x}")
                return magic
        except:
            continue
    
    logger.info("[DEBUG] No valid magic found in overlay")
    return None

class CTOCEntry:
    def __init__(
        self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name
    ):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name

class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24  # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64  # For pyinstaller 2.1+
    
    def __init__(self, path):
        self.filePath = path
        self.pycMagic = b"\0" * 4
        self.barePycList = []  # List of pyc's whose headers have to be fixed
        self.cryptoKey = None
        self.cryptoKeyFileData = None
        self.MAGIC = find_pyinstaller_magic(path)
        logger.info(f"[+] Extracted magic: 0x{struct.unpack('<Q', self.MAGIC)[0]:x}")

    def open(self):
        try:
            self.fPtr = open(self.filePath, "rb")
            self.fileSize = os.stat(self.filePath).st_size
        except:
            logger.error("[!] Error: Could not open {0}".format(self.filePath))
            return False
        return True

    def close(self):
        try:
            self.fPtr.close()
        except:
            pass

    def checkFile(self):
        logger.info("[+] Processing {0}".format(self.filePath))

        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            logger.error("[!] Error: File is too short or truncated")
            return False

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            logger.error(
                "[!] Error: Missing cookie, unsupported pyinstaller version or not a pyinstaller archive"
            )
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b"python" in self.fPtr.read(64).lower():
            logger.info("[+] Pyinstaller version: 2.1+")
            self.pyinstVer = 21  # pyinstaller 2.1+
        else:
            self.pyinstVer = 20  # pyinstaller 2.0
            logger.info("[+] Pyinstaller version: 2.0")

        return True

    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver) = struct.unpack(
                    "!8siiii", self.fPtr.read(self.PYINST20_COOKIE_SIZE)
                )

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = struct.unpack(
                    "!8sIIii64s", self.fPtr.read(self.PYINST21_COOKIE_SIZE)
                )

        except:
            logger.error("[!] Error: The file is not a pyinstaller archive")
            return False

        self.pymaj, self.pymin = (
            (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        )
        logger.info("[+] Python version: {0}.{1}".format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = (
            self.fileSize
            - self.cookiePos
            - (
                self.PYINST20_COOKIE_SIZE
                if self.pyinstVer == 20
                else self.PYINST21_COOKIE_SIZE
            )
        )

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        logger.info("[+] Length of package: {0} bytes".format(lengthofPackage))
        return True

    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize,) = struct.unpack("!i", self.fPtr.read(4))
            nameLen = struct.calcsize("!iIIIBc")

            (
                entryPos,
                cmprsdDataSize,
                uncmprsdDataSize,
                cmprsFlag,
                typeCmprsData,
                name,
            ) = struct.unpack(
                "!IIIBc{0}s".format(entrySize - nameLen), self.fPtr.read(entrySize - 4)
            )

            try:
                name = name.decode("utf-8").rstrip("\0")
            except UnicodeDecodeError:
                newName = str(uniquename())
                logger.info('[!] Warning: File name {0} contains invalid bytes. Using random name {1}'.format(name, newName))
                name = newName

            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())
                logger.info(
                    "[!] Warning: Found an unamed file in CArchive. Using random name {0}".format(
                        name
                    )
                )

            self.tocList.append(
                CTOCEntry(
                    self.overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name,
                )
            )

            parsedLen += entrySize
        logger.info("[+] Found {0} files in CArchive".format(len(self.tocList)))

    def _writeRawData(self, filepath, data):
        nm = (
            filepath.replace("\\", os.path.sep)
            .replace("/", os.path.sep)
            .replace("..", "__")
        )
        nmDir = os.path.dirname(nm)
        if nmDir != "" and not os.path.exists(
            nmDir
        ):  # Check if path exists, create if not
            os.makedirs(nmDir)

        with open(nm, "wb") as f:
            f.write(data)

    def extractFiles(self, one_dir):
        logger.info("[+] Beginning extraction...please standby")
        extractionDir = os.path.join(
            os.getcwd(), os.path.basename(self.filePath) + "_extracted"
        )

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize  # Sanity Check

            if entry.typeCmprsData == b"d" or entry.typeCmprsData == b"o":
                # d -> ARCHIVE_ITEM_DEPENDENCY
                # o -> ARCHIVE_ITEM_RUNTIME_OPTION
                # These are runtime options, not files
                continue

            basePath = os.path.dirname(entry.name)
            if basePath != "":
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            if entry.typeCmprsData == b"s":
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts
                logger.info("[+] Possible entry point: {0}.pyc".format(entry.name))

                if self.pycMagic == b"\0" * 4:
                    # if we don't have the pyc header yet, fix them in a later pass
                    self.barePycList.append(entry.name + ".pyc")
                self._writePyc(entry.name + ".pyc", data)

            elif entry.typeCmprsData == b"M" or entry.typeCmprsData == b"m":
                # M -> ARCHIVE_ITEM_PYPACKAGE
                # m -> ARCHIVE_ITEM_PYMODULE
                # packages and modules are pyc files with their header intact

                # From PyInstaller 5.3 and above pyc headers are no longer stored
                # https://github.com/pyinstaller/pyinstaller/commit/a97fdf
                if data[2:4] == b"\r\n":
                    # < pyinstaller 5.3
                    if self.pycMagic == b"\0" * 4:
                        self.pycMagic = data[0:4]
                    self._writeRawData(entry.name + ".pyc", data)

                    if entry.name.endswith("_crypto_key"):
                        logger.info(
                            "[+] Detected _crypto_key file, saving key for automatic decryption"
                        )
                        # This is a pyc file with a header (8,12, or 16 bytes)
                        # Extract the code object after the header
                        self.cryptoKeyFileData = self._extractCryptoKeyObject(data)

                else:
                    # >= pyinstaller 5.3
                    if self.pycMagic == b"\0" * 4:
                        # if we don't have the pyc header yet, fix them in a later pass
                        self.barePycList.append(entry.name + ".pyc")

                    self._writePyc(entry.name + ".pyc", data)

                    if entry.name.endswith("_crypto_key"):
                        logger.info(
                            "[+] Detected _crypto_key file, saving key for automatic decryption"
                        )
                        # This is a plain code object without a header
                        self.cryptoKeyFileData = data

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b"z" or entry.typeCmprsData == b"Z":
                    self._extractPyz(entry.name, one_dir)

        # Fix bare pyc's if any
        self._fixBarePycs()

    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, "r+b") as pycFile:
                # Overwrite the first four bytes
                pycFile.write(self.pycMagic)

    def _extractCryptoKeyObject(self, data):
        logger.info("pymaj", self.pymaj)
        if self.pymaj >= 3 and self.pymin >= 7:
            # 16 byte header for 3.7 and above
            return data[16:]
        elif self.pymaj >= 3 and self.pymin >= 3:
            # 12 byte header for 3.3-3.6
            return data[12:]
        else:
            # 8 byte header for 2.x, 3.0-3.2
            return data[8:]

    def _writePyc(self, filename, data):
        with open(filename, "wb") as pycFile:
            pycFile.write(self.pycMagic)  # pyc magic

            if self.pymaj >= 3 and self.pymin >= 7:  # PEP 552 -- Deterministic pycs
                pycFile.write(b"\0" * 4)  # Bitfield
                pycFile.write(b"\0" * 8)  # (Timestamp + size) || hash

            else:
                pycFile.write(b"\0" * 4)  # Timestamp
                if self.pymaj >= 3 and self.pymin >= 3:
                    pycFile.write(b"\0" * 4)  # Size parameter added in Python 3.3

            pycFile.write(data)

    def _getCryptoKey(self):
        if self.cryptoKey:
            return self.cryptoKey

        if not self.cryptoKeyFileData:
            return None

        co = load_code(self.cryptoKeyFileData, pycHeader2Magic(self.pycMagic))
        self.cryptoKey = co.co_consts[0]
        return self.cryptoKey

    def _tryDecrypt(self, ct, aes_mode):
        CRYPT_BLOCK_SIZE = 16
        k = self._getCryptoKey()
        key = bytes(k, "utf-8")
        assert len(key) == 16

        # Initialization vector
        iv = ct[:CRYPT_BLOCK_SIZE]

        if aes_mode == "ctr":
            # Pyinstaller >= 4.0 uses AES in CTR mode
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
            cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
            return cipher.decrypt(ct[CRYPT_BLOCK_SIZE:])

        elif aes_mode == "cfb":
            # Pyinstaller < 4.0 uses AES in CFB mode
            cipher = AES.new(key, AES.MODE_CFB, iv)
            return cipher.decrypt(ct[CRYPT_BLOCK_SIZE:])            

    def extract_xor_keys_from_pyc(self, pyc_path):
        """
        Extract BOTH XOR keys from pyimod01_archive.pyc
        Returns a tuple of (key1, key2) as bytes, or (None, None) if not found.
        """
        try:
            with open(pyc_path, 'rb') as f:
                # Skip the pyc header (16 bytes for Python 3.7+)
                f.read(16)
                
                # Load the code object
                code = marshal.load(f)
            
            # Find the ZlibArchiveReader class
            for const in code.co_consts:
                if hasattr(const, 'co_name') and const.co_name == 'ZlibArchiveReader':
                    # Found the class, now find the extract method
                    for class_const in const.co_consts:
                        if hasattr(class_const, 'co_name') and class_const.co_name == 'extract':
                            # Found extract method, collect all XOR keys from genexpr
                            xor_keys = []
                            for extract_const in class_const.co_consts:
                                if hasattr(extract_const, 'co_name') and extract_const.co_name == '<genexpr>':
                                    # Check if this genexpr has a bytes constant (the XOR key)
                                    for genexpr_const in extract_const.co_consts:
                                        if isinstance(genexpr_const, bytes) and len(genexpr_const) > 0:
                                            xor_keys.append(genexpr_const)
                            
                            if len(xor_keys) >= 2:
                                logger.info(f"[+] Found XOR key 1: {xor_keys[0]}")
                                logger.info(f"[+] Found XOR key 2: {xor_keys[1]}")
                                return xor_keys[0], xor_keys[1]
                            elif len(xor_keys) == 1:
                                logger.info(f"[!] Only found one XOR key: {xor_keys[0]}")
                                return xor_keys[0], None
                            else:
                                logger.info("[!] No XOR keys found in genexpr")
        except Exception as e:
            logger.info(f"[!] Error extracting XOR keys: {e}")
            import traceback
            traceback.print_exc()
        
        return None, None

    def _extractPyz(self, name, one_dir):
        dirName = "." if one_dir else name + "_extracted"
        if not one_dir and not os.path.exists(dirName):
            os.mkdir(dirName)
        # Try to extract XOR keys from pyimod01_archive.pyc
        pyimod_path = "pyimod01_archive.pyc"
        xor_key1, xor_key2 = None, None
        
        if os.path.exists(pyimod_path):
            xor_key1, xor_key2 = self.extract_xor_keys_from_pyc(pyimod_path)
        
        if not xor_key1 or not xor_key2:
            logger.info("[!] Could not extract XOR keys from pyimod01_archive.pyc")
            logger.info("[!] Attempting extraction without XOR decryption...")

        with open(name, "rb") as f:
            pyzPycMagic = f.read(4)
            if self.pycMagic == b"\0" * 4:
                self.pycMagic = pyzPycMagic
            elif self.pycMagic != pyzPycMagic:
                self.pycMagic = pyzPycMagic
                logger.info("[!] Warning: pyc magic of files inside PYZ archive are different from those in CArchive")

            (tocPosition,) = struct.unpack("!i", f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.loads(f.read())
            except:
                logger.info("[!] Unmarshalling FAILED.")
                return

            logger.info("[+] Found {0} files in PYZ archive".format(len(toc)))

            if type(toc) == list:
                toc = dict(toc)
            
            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = str(key).replace("..", "__").replace(".", os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, "__init__.pyc")
                else:
                    filePath = os.path.join(dirName, fileName + ".pyc")

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    
                    # Apply XOR decryption if keys were found
                    if xor_key1 and xor_key2:
                        # Step 1: XOR with first key
                        data = bytes(b ^ xor_key1[i % len(xor_key1)] for i, b in enumerate(data))
                        
                        # Step 2: Decompress
                        data = zlib.decompress(data)
                        
                        # Step 3: XOR with second key
                        data = bytes(b ^ xor_key2[i % len(xor_key2)] for i, b in enumerate(data))
                        
                        # Step 4: Reverse
                        data = data[::-1]
                    else:
                        # Try standard decompression without XOR
                        data = zlib.decompress(data)
                    
                    self._writePyc(filePath, data)
                except Exception as e:
                    logger.info(f"[!] Error extracting {filePath}: {e}")
                    continue

            logger.info(f"[+] Successfully extracted {len(toc)} PYZ files")
