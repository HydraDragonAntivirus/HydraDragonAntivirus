#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import lzma
import pefile
from dataclasses import dataclass
from typing import Optional
from hydradragon.antivirus_scripts.hydra_logger import logger

# PE file format constants
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
LZMA_PROPERTIES_SIZE = 5  # Standard LZMA properties size

@dataclass
class PACKER_INFO:
    """Python implementation corresponding to C++ struct"""
    Src: int  # uint32
    Dst: int  # uint32

def to_hex_string(val, prefix=True):
    """Convert value to hexadecimal string for better error message display"""
    return f"0x{val:x}" if prefix else f"{val:x}"

def find_pattern(data: bytes, pattern: bytes) -> Optional[int]:
    """
    Find pattern in data, supporting 0xFF as wildcard
    Returns position where found, or None if not found
    """
    if not pattern or len(data) < len(pattern):
        return None

    for i in range(len(data) - len(pattern) + 1):
        match = True
        for j in range(len(pattern)):
            if pattern[j] != 0xFF and data[i + j] != pattern[j]:
                match = False
                break
        if match:
            return i
    return None

def unpack_pe(packed_pe_data: bytes) -> bytes:
    """
    Unpack a VMProtect protected PE file
    """
    if not packed_pe_data:
        raise RuntimeError("Packed PE data is null or empty.")

    try:
        pe = pefile.PE(data=packed_pe_data)
    except pefile.PEFormatError as e:
        raise RuntimeError(f"Invalid PE file format: {str(e)}")

    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders

    unpacked_image = bytearray(size_of_image)
    unpacked_image[:size_of_headers] = packed_pe_data[:size_of_headers]

    rva_patterns_array = []
    for section in pe.sections:
        condition1 = (section.SizeOfRawData == 0)
        condition2 = (section.PointerToRawData == 0)
        condition3 = not (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)

        if condition1 and condition2 and condition3:
            pattern_value = ((section.VirtualAddress << 32) | 0xFFFFFFFF) & 0xFFFFFFFFFFFFFFFF
            pattern_bytes = struct.pack("<Q", pattern_value)
            rva_patterns_array.append(pattern_bytes)

    packer_info_array = []
    num_packer_entries = 0

    if rva_patterns_array:
        pattern_bytes = b''.join(rva_patterns_array)
        pattern_pos = find_pattern(packed_pe_data, pattern_bytes)

        if pattern_pos is not None:
            if pattern_pos < 8:
                raise RuntimeError("Located RVA pattern is too close to the beginning of the file to precede PACKER_INFO[0].")

            packer_info_offset = pattern_pos - 8
            num_packer_entries = len(rva_patterns_array)

            if num_packer_entries > 0:
                end_of_packer_info_array = packer_info_offset + (num_packer_entries + 1) * 8
                if end_of_packer_info_array > len(packed_pe_data) or packer_info_offset < 0:
                    raise RuntimeError("Located PACKER_INFO array extends beyond packed PE buffer or has invalid start.")

            for j in range(num_packer_entries + 1):
                info_offset = packer_info_offset + j * 8
                src = struct.unpack("<I", packed_pe_data[info_offset:info_offset+4])[0]
                dst = struct.unpack("<I", packed_pe_data[info_offset+4:info_offset+8])[0]
                packer_info_array.append(PACKER_INFO(src, dst))
        else:
            raise RuntimeError("RVA pattern sequence for PACKER_INFO not found in packed PE, but patterns were expected.")
    else:
        logger.info("RVA pattern array is empty. No PACKER_INFO entries to process for LZMA.")

    for i, section in enumerate(pe.sections):
        virtual_address = section.VirtualAddress
        virtual_size = section.Misc_VirtualSize
        size_of_raw_data = section.SizeOfRawData
        pointer_to_raw_data = section.PointerToRawData
        section_name = section.Name.decode('ascii', errors='ignore').strip('\0')

        if pointer_to_raw_data != 0 and size_of_raw_data > 0:
            if pointer_to_raw_data + size_of_raw_data <= len(packed_pe_data) and virtual_address + size_of_raw_data <= size_of_image:
                section_data = packed_pe_data[pointer_to_raw_data:pointer_to_raw_data+size_of_raw_data]
                unpacked_image[virtual_address:virtual_address+len(section_data)] = section_data
            else:
                logger.error(f"Section {section_name} data exceeds boundaries. RawOffset={to_hex_string(pointer_to_raw_data)}, "
                              f"RawSize={to_hex_string(size_of_raw_data)}, VA={to_hex_string(virtual_address)}. Skipping copy.")

        section_offset = pe.OPTIONAL_HEADER.get_file_offset() + pe.FILE_HEADER.SizeOfOptionalHeader + i * 40
        unpacked_section_offset = section_offset

        struct.pack_into("<I", unpacked_image, unpacked_section_offset+20, virtual_address)
        if virtual_size > 0:
            struct.pack_into("<I", unpacked_image, unpacked_section_offset+16, virtual_size)

    if packer_info_array and len(packer_info_array) > 1:
        props_info = packer_info_array[0]
        props_raw_offset = pe.get_offset_from_rva(props_info.Src)

        lzma_props_size = props_info.Dst
        lzma_props_data = packed_pe_data[props_raw_offset:props_raw_offset+lzma_props_size]

        if props_raw_offset + lzma_props_size > len(packed_pe_data):
            raise RuntimeError("LZMA properties data extends beyond packed PE size.")

        if lzma_props_size != LZMA_PROPERTIES_SIZE:
            logger.error(f"PACKER_INFO[0].Dst (LZMA properties size) is {lzma_props_size}. Standard is {LZMA_PROPERTIES_SIZE}. Using provided size.")

        try:
            for block_idx in range(1, len(packer_info_array)):
                current_block_info = packer_info_array[block_idx]
                compressed_data_rva = current_block_info.Src
                uncompressed_target_rva = current_block_info.Dst

                try:
                    compressed_block_raw_offset = pe.get_offset_from_rva(compressed_data_rva)
                except Exception as e:
                    raise RuntimeError(f"Block {block_idx}: Cannot convert RVA to file offset: {str(e)}")

                compressed_data = packed_pe_data[compressed_block_raw_offset:]

                if uncompressed_target_rva >= size_of_image:
                    raise RuntimeError(f"Block {block_idx}: PACKER_INFO.Dst (decompression target RVA {to_hex_string(uncompressed_target_rva)}) exceeds image boundary.")

                lc = lzma_props_data[0] % 9
                lp = (lzma_props_data[0] // 9) % 5
                pb = lzma_props_data[0] // 45
                dict_size = int.from_bytes(lzma_props_data[1:5], byteorder='little')

                filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": lc, "lp": lp, "pb": pb}]

                decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)

                try:
                    decompressed_data = decompressor.decompress(compressed_data)
                    available_space = size_of_image - uncompressed_target_rva
                    if len(decompressed_data) <= available_space:
                        unpacked_image[uncompressed_target_rva:uncompressed_target_rva+len(decompressed_data)] = decompressed_data
                    else:
                        logger.error(f"Block {block_idx}: Decompressed data size exceeds available space in image")
                        unpacked_image[uncompressed_target_rva:uncompressed_target_rva+available_space] = decompressed_data[:available_space]

                    logger.info(f"Block {block_idx}: Decompressed. Output size={len(decompressed_data)}")
                except lzma.LZMAError as e:
                    raise RuntimeError(f"LZMA decompression error: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error processing LZMA data: {str(e)}")

    return bytes(unpacked_image)
