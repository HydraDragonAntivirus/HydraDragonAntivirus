# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ----------------------------------------------------------------------

import lief
import logging as logger
import datetime
import GoStringUngarbler.ungarblers
import GoStringUngarbler.patterns
import GoStringUngarbler.patchers
from typing import Optional, Dict, Any

def get_binary_architecture(lief_binary: lief.Binary) -> str:
    """
    Returns the binary architecture ('386' for 32-bit or 'AMD64' for 64-bit).
    
    Args:
        lief_binary (lief.Binary): The parsed binary object.
        
    Raises:
        Exception: If the architecture is not supported.
    
    Returns:
        str: '386' or 'AMD64'
    """
    if isinstance(lief_binary, lief.PE.Binary):
        if lief_binary.header.machine == lief.PE.Header.MACHINE_TYPES.I386:
            return '386'
        elif lief_binary.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64:
            return 'AMD64'
    elif isinstance(lief_binary, lief.ELF.Binary):
        if lief_binary.header.identity_class == lief.ELF.Header.CLASS.ELF32.value:
            return '386'
        elif lief_binary.header.identity_class == lief.ELF.Header.CLASS.ELF64.value:
            return 'AMD64'
    raise Exception("Architecture not supported")

def process_data(input_data: bytes) -> Dict[str, Any]:
    """
    Processes binary data to deobfuscate and patch a garbled executable.
    
    Args:
        input_data (bytes): The binary data of the garbled executable.
        
    Returns:
        dict: A dictionary containing processing results, including:
            - patched_data: The patched binary data.
            - decrypt_func_list: List of functions that were decrypted.
            - error_count: The number of errors that occurred.
            - stack_func_count, split_func_count, seed_func_count: Counts of obfuscated string functions.
            - processing_time_ms: Processing time in milliseconds.
            - error_list: A list of functions for which errors occurred.
    """
    lief_binary = lief.parse(input_data)
    if lief_binary is None:
        raise Exception("Not a valid PE/ELF file")
    
    arch = get_binary_architecture(lief_binary)
    
    if arch == '386':
        ungarbler_instance = ungarblers.GoStringUngarblerX86(lief_binary, input_data)
        pattern_instance = patterns.GarblerPatternX86(input_data)
        patcher_instance = patchers.PatcherX86(pattern_instance)
    elif arch == 'AMD64':
        ungarbler_instance = ungarblers.GoStringUngarblerX64(lief_binary, input_data)
        pattern_instance = patterns.GarblerPatternX64(input_data)
        patcher_instance = patchers.PatcherX64(pattern_instance)
    
    start = datetime.datetime.now()
    
    # Locate decryption routines using defined patterns.
    ungarbler_instance.find_string_decryption_routine(patterns.STACK_STRING_DECRYPTION, pattern_instance)
    ungarbler_instance.find_string_decryption_routine(patterns.SPLIT_STRING_DECRYPTION, pattern_instance)
    ungarbler_instance.find_string_decryption_routine(patterns.SEED_STRING_DECRYPTION, pattern_instance)
    
    error_count = 0
    error_list_func = []
    
    for i, func in enumerate(ungarbler_instance.decrypt_func_list, start=1):
        try:
            decrypted_str = ungarbler_instance.emulate(func)
            if decrypted_str:
                func.set_decrypted_string(decrypted_str)
                logger.info('%d/%d - Function at 0x%x: %s', 
                            i, len(ungarbler_instance.decrypt_func_list), 
                            func.func_start_va, repr(decrypted_str))
                patcher_instance.generate_patch(func)
        except Exception as e:
            logger.debug('Emulation error: %s', str(e))
            error_list_func.append(func)
            error_count += 1
    
    patched_data = patcher_instance.apply_patches(input_data)
    
    end = datetime.datetime.now()
    processing_time_ms = (end - start).total_seconds() * 1000
    
    results = {
        "patched_data": patched_data,
        "decrypt_func_list": ungarbler_instance.decrypt_func_list,
        "error_count": error_count,
        "stack_func_count": ungarbler_instance.stack_func_count,
        "split_func_count": ungarbler_instance.split_func_count,
        "seed_func_count": ungarbler_instance.seed_func_count,
        "processing_time_ms": processing_time_ms,
        "error_list": error_list_func,
    }
    
    return results

def process_file_go(input_path: str, 
                 output_path: Optional[str] = None, 
                 string_output_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Processes a binary file, deobfuscates and patches it, and optionally writes the output to files.
    
    Args:
        input_path (str): Path to the garbled executable.
        output_path (Optional[str]): If provided, the patched binary will be written to this path.
        string_output_path (Optional[str]): If provided, the extracted strings will be written to this path.
    
    Returns:
        dict: A dictionary containing processing results (same as process_data).
    """
    with open(input_path, 'rb') as f:
        input_data = f.read()
    
    results = process_data(input_data)
    
    # Write the patched binary if an output path is provided.
    if output_path and results.get("patched_data"):
        with open(output_path, 'wb') as out_file:
            out_file.write(results["patched_data"])
        logger.info('Patched binary written to %s', output_path)
    
    # Write extracted strings if a string output path is provided.
    if string_output_path:
        with open(string_output_path, 'w') as str_file:
            for func in results["decrypt_func_list"]:
                if func.decrypted_string:
                    str_file.write(repr(func.decrypted_string) + '\n')
        logger.info('Extracted strings written to %s', string_output_path)
    
    return results
