#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import os

#inspired by https://aluigi.altervista.org/bms/advanced_installer.bms
#with some additionaly reverse engeneering, quite heursitic (footer search, xor guessing etc)
#licence: public domain
# https://gist.github.com/KasparNagu/9ee02cb62d81d9e4c7a833518a710d6e

class AdvancedInstallerFileInfo:
    def __init__(self, name, size, offset, xorSize):
        self.name = name
        self.size = size
        self.offset = offset
        self.xorSize = xorSize

    def __repr__(self):
        return "[%s size=%d offset=%d]" % (self.name, self.size, self.offset)


class AdvancedInstallerFileReader:
    def __init__(self, filehandle, size, keepOpen, xorLength):
        self.filehandle = filehandle
        self.size = size
        self.xorLength = xorLength
        self.pos = 0
        self.keepOpen = keepOpen

    def xorFF(self, block):
        if isinstance(block, str):
            return "".join([chr(ord(i) ^ 0xff) for i in block])
        else:
            return bytes([i ^ 0xff for i in block])

    def read(self, size=None):
        if size is None:
            return self.read(self.size - self.pos)
        if self.pos < self.xorLength:
            xorLen = min(self.xorLength - self.pos, size)
            xorBlock = self.filehandle.read(xorLen)
            xorLenEffective = len(xorBlock)
            self.pos += xorLenEffective
            xorBlock = self.xorFF(xorBlock)
            if xorLenEffective < size:
                return xorBlock + self.read(size - xorLenEffective)
            return xorBlock
        blk = self.filehandle.read(min(size, self.size - self.pos))
        self.pos += len(blk)
        return blk

    def close(self):
        if not self.keepOpen:
            self.filehandle.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()


class AdvancedInstallerReader:
    def __init__(self, filename, debug=None):
        self.filename = filename
        self.filehandle = open(filename, "rb")
        self.search_back = 10000
        self.xorSize = 0x200
        self.footer_position = None
        self.debug = debug
        self.threadsafeReopen = False
        self.files = []

    def close(self):
        self.filehandle.close()

    def search_footer(self):
        for i in range(0, 10000):
            self.filehandle.seek(-i, os.SEEK_END)
            magic = self.filehandle.read(10)
            if magic == b"ADVINSTSFX":
                self.footer_position = i + 0x48 - 12
                break
        if self.footer_position is None:
            logger.error("ADVINSTSFX not found")

    def read_footer(self):
        if self.footer_position is None:
            self.search_footer()
        self.filehandle.seek(-self.footer_position, os.SEEK_END)
        footer = self.filehandle.read(0x48)

        if self.debug:
            self.debug.write("Footer data (%d bytes): %s\n" % (len(footer), footer.hex()))

        # Try different unpacking strategies based on actual footer structure
        try:
            # Original format - try first
            offset, self.nfiles, _, offset1, self.info_off, file_off, hexhash, _, name = struct.unpack(
                "<llllll32sl12s", footer)
        except struct.error:
            try:
                # Alternative format without the last name field
                data = struct.unpack("<llllll32sl", footer[:60])
                offset, self.nfiles, _, offset1, self.info_off, file_off, hexhash, _ = data
                name = footer[60:] if len(footer) > 60 else b""
            except struct.error:
                try:
                    # Simplified format - just the essential fields
                    data = struct.unpack("<llllll", footer[:24])
                    offset, self.nfiles, _, offset1, self.info_off, file_off = data
                    hexhash = footer[24:56] if len(footer) > 56 else b""
                    name = footer[56:] if len(footer) > 56 else b""
                except struct.error:
                    # Last resort - extract what we can
                    if len(footer) >= 8:
                        offset, self.nfiles = struct.unpack("<ll", footer[:8])
                        offset1 = 0
                        self.info_off = struct.unpack("<l", footer[16:20])[0] if len(footer) >= 20 else 0
                        file_off = struct.unpack("<l", footer[20:24])[0] if len(footer) >= 24 else 0
                    else:
                        logger.error("Footer too short to parse")
                    hexhash = b""
                    name = b""

        if self.debug:
            self.debug.write(
                "offset=%d files=%d offset1=%d  info_off=%d file_off=%d hexhash=%s name=%s\n" % (offset, self.nfiles,
                                                                                                 offset1, self.info_off,
                                                                                                 file_off, hexhash,
                                                                                                 name))

    def read_info(self):
        self.read_footer()
        self.files = []
        self.filehandle.seek(self.info_off, os.SEEK_SET)
        for i in range(0, self.nfiles):
            info = self.filehandle.read(24)
            if len(info) < 24:
                if self.debug:
                    self.debug.write("Warning: incomplete info block for file %d\n" % i)
                break
            _, _, xor_flag, size, offset, namesize = struct.unpack("<llllll", info)
            if self.debug:
                self.debug.write(
                    " size=%d offset=%d namesize=%d xor_flag=0x%x\n" % (size, offset, namesize, xor_flag))
            if 0 < namesize < 0xFFFF:
                name_data = self.filehandle.read(namesize * 2)
                if len(name_data) == namesize * 2:
                    try:
                        name = name_data.decode("UTF-16LE")
                        # Remove null terminator if present
                        name = name.rstrip('\x00')
                    except UnicodeDecodeError:
                        # Fallback to UTF-16BE or raw bytes
                        try:
                            name = name_data.decode("UTF-16BE")
                            name = name.rstrip('\x00')
                        except UnicodeDecodeError:
                            name = "file_%d.bin" % i
                    if self.debug:
                        self.debug.write("  name=%s\n" % name)
                    self.files.append(AdvancedInstallerFileInfo(name, size, offset, self.xorSize if xor_flag == 2 else 0))
                else:
                    if self.debug:
                        self.debug.write("Warning: incomplete name data for file %d\n" % i)
            elif namesize == 0:
                # Handle files with no name
                name = "unnamed_file_%d.bin" % i
                if self.debug:
                    self.debug.write("  name=%s (unnamed)\n" % name)
                self.files.append(AdvancedInstallerFileInfo(name, size, offset, self.xorSize if xor_flag == 2 else 0))
            else:
                if self.debug:
                    self.debug.write("Warning: Invalid name size %d for file %d\n" % (namesize, i))
                # Skip this file or use a default name
                continue

    def open(self, infoFile):
        if isinstance(infoFile, AdvancedInstallerFileInfo):
            if self.threadsafeReopen:
                fh = open(self.filename, "rb")
            else:
                fh = self.filehandle
            fh.seek(infoFile.offset, os.SEEK_SET)
            return AdvancedInstallerFileReader(fh, infoFile.size, not self.threadsafeReopen, infoFile.xorSize)
        else:
            if not self.files:
                self.read_info()
            for f in self.files:
                if f.name == infoFile:
                    return self.open(f)
        return None

    def infolist(self):
        if not self.files:
            self.read_info()
        return self.files

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __repr__(self):
        return "[path=%s footer=%s nFiles=%d]" % (self.filename, self.footer_position, len(self.files))
