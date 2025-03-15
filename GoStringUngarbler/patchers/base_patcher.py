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

from abc import ABC, abstractmethod
from typing import List
from GoStringUngarbler.patterns import GarblerPattern, STACK_STRING_DECRYPTION, SPLIT_STRING_DECRYPTION, SEED_STRING_DECRYPTION

class Function:
    """
    Class for a string decoding function
    
    Attributes
    ----------

    data: bytes 
        
        Function body data
    
    func_start_va: int 
            
        Function start virtual address
        
    func_start_emu_va: int
        
        Function start virtual address to emulate (skip prologue's stack check)

    func_start_offset: int 
            
        Function start offset (for patching)
        
    func_end_va: int 
            
        Function end virtual address (at the return instruction) 
        
    decrypted_string: str
            
        Decrypted string extracted after emulation
        
    emu_stop_va: int 
            
        Virtual address to stop emulation (at call runtime_slicebytetostring)

    type: int
        Type of string decryption. Possible values is STACK_STRING_DECRYPTION, 
        SPLIT_STRING_DECRYPTION, SEED_STRING_DECRYPTION
    """

    def __init__(self, data: bytes=None, func_start_offset: int=0, func_start_va: int=0, func_start_emu_va: int=0, func_end_va: int=0, emu_stop_va: int=0, type: int=STACK_STRING_DECRYPTION):
        """
        Constructor for Function class

        Args:
            data (bytes, optional): Function body data. Defaults to None.
            func_start_offset (int, optional): Function start offset. Defaults to 0.
            func_start_va (int, optional): Function start virtual address. Defaults to 0.
            func_start_emu (int, optional): Function start virtual address to emulate (skip prologue's stack check). Defaults to 0.
            func_end_va (int, optional): Function end virtual address. Defaults to 0.
            emu_stop_va (int, optional): Virtual address to stop emulation. Defaults to 0.
            type (int, optional): Type of decryption. Defaults to pattern.STACK_STRING_DECRYPTION
        """
        
        self.data = data
        self.func_start_va = func_start_va
        self.func_start_emu_va = func_start_emu_va
        self.func_start_offset = func_start_offset
        self.func_end_va = func_end_va
        self.decrypted_string = ''
        self.emu_stop_va = emu_stop_va
        self.type = type
        if self.type not in [STACK_STRING_DECRYPTION, SPLIT_STRING_DECRYPTION, SEED_STRING_DECRYPTION]:
            raise Exception("Decryption type invalid")
        
    def set_decrypted_string(self, decrypted_string: str):
        """
        Decrypted string setter

        Args:
            decrypted_string (str): Decrypted string extracted after emulation
        """
        self.decrypted_string = decrypted_string

    def __str__(self) -> str:
        """
        To string function

        Returns:
            str: String representation of the Function object
        """
        result = ''
        result += 'Function sub_' + hex(self.func_start_va)[2:] + '\n'
        result += '\tFunction start: ' + hex(self.func_start_va) + '\n'
        result += '\tFunction end: ' + hex(self.func_end_va) + '\n'
        result += '\tFunction stop address: ' + hex(self.emu_stop_va) + '\n'
        return result

class Patch:
    """
    Class for a patch
    
    Attributes
    ----------
    patch_data: bytes 
    
        Patched function body data
    
    patch_offset: int 
            
        File offset to patch the function at
    """
    
    def __init__(self, patch_data: bytes, patch_offset: int):
        """
        Constructor for the Patch class

        Args:
            patch_data (bytes): Patched function body data
            patch_offset (int): File offset to patch the function at
        """
        self.patch_data: bytes = patch_data
        self.patch_offset: int = patch_offset

class Patcher(ABC):
    """
    Base class for the patcher engine
    
    Attributes
    ----------
    patches: List[Patch] 
    
        List of all patches to apply to the Go executable
        
    garble_pattern: GarblerPattern
    
        Garbler pattern we're applying
    """
    
    def __init__(self, garble_pattern: GarblerPattern):
        """
        Constructor for the patcher
        """
        self.patches: List[Patch] = []
        self.garble_pattern: GarblerPattern = garble_pattern
    
    def __str__(self) -> str:
        """
        Patcher to string

        Returns:
            str: String representation of the Patcher object
        """
        result = ''
        for patch in self.patches:
            result += '[+] Patching at ' + hex(patch.patch_offset)
            result += '\n\t' + self.to_hex_string(patch.patch_data)
            result += '\n---------------------------------------------\n'
        return result
    
    def to_hex_string(self, data: bytes) -> str:
        """
        To hex string representation

        Args:
            data (bytes): Input data

        Returns:
            str: Hex string representation of the input data
        """
        result = ''
        for each in data:
            each = hex(each)[2:]
            if len(each) == 1:
                result += '0'
            result += each + ' '
        return result

    @abstractmethod
    def generate_patch(self, func: Function):
        """
        Generate a patch for a Function object

        Args:
            func (Function): String decoding function to patch
        """
        pass

    def apply_patches(self, input_data: bytes) -> bytes:
        """
        Apply patches to generate deobfuscated file

        Args:
            input_data (bytes): Garble-obfuscated file data

        Returns:
            bytes: deobfuscated file data
        """
        if len(self.patches) == 0:
            return None
        
        input_data = bytearray(input_data)
        for patch in self.patches:
            input_data[patch.patch_offset:patch.patch_offset + len(patch.patch_data)] = patch.patch_data

        return bytes(input_data)