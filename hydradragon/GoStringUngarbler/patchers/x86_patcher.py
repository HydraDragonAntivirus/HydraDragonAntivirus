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

from .base_patcher import Patcher, Function, Patch
from GoStringUngarbler.patterns import GarblerPattern
import re
import struct

class PatcherX86(Patcher):
    """
    Class for x64 patcher

    """
    
    def __init__(self, garble_pattern: GarblerPattern):
        """
        Constructor for the patcher
        """
        super().__init__(garble_pattern)


    def generate_patch(self, func: Function):
        """
        Generate a patch for a Function object

        Args:
            func (Function): String decrypting function to patch
        """
        
        slicebytetostring_va = 0
        
        # get runtime_sliceByteToString virtual address
        epilogue_pattern = self.garble_pattern.get_epilogue_pattern(func.type).pattern
        
        epilogue_pattern = epilogue_pattern[:epilogue_pattern.find(rb'\xE8[\S\s]')]

        match = re.search(epilogue_pattern, func.data)
        if match is None:
            raise Exception('Can not find epilogue')
        
        slicebytetostring_call_offset = match.end()
        instruction_after_call_offset = slicebytetostring_call_offset + 5
        slicebytetostring_rel_offset = struct.unpack('<I', func.data[slicebytetostring_call_offset + 1:instruction_after_call_offset])[0]
        
        if slicebytetostring_rel_offset >> 31 == 1:
            # negative, flip 2's comp
            slicebytetostring_rel_offset = ~slicebytetostring_rel_offset
            slicebytetostring_rel_offset += 1
            slicebytetostring_rel_offset &= 0xFFFFFFFF
            slicebytetostring_va = func.func_start_va + instruction_after_call_offset - slicebytetostring_rel_offset
        else:
            slicebytetostring_va = func.func_start_va + instruction_after_call_offset + slicebytetostring_rel_offset

        patch_data = b''
        
        # skip prologue, only write the sub instruction to allocate stack for local variables
        
        # find sub esp, <stack size>
        prologue_data = func.data[func.data.find(b'\x83\xEC'):func.data.find(b'\x83\xEC') + 3]
        
        patch_data += prologue_data
        
        # write 
        # E8 00 00 00 00             ; call $+5
        # 58                         ; pop eax        ; eax now contains current address
        # 83 C0 29                   ; add eax, 0x29    ; offset to decrypted string below the function
        
        patch_data += b'\xE8\x00\x00\x00\x00'
        patch_data += b'\x58'
        patch_data += b'\x83\xC0\x29'

        # mov DWORD PTR [esp+0x4], eax
        patch_data += b'\x89\x44\x24\x04'
        
        # mov DWORD PTR [esp+0x8], <length>
        patch_data += b'\xC7\x44\x24\x08' + struct.pack('I', len(func.decrypted_string))

        # call runtime_slicebytetostring | e8 <relative offset to runtime_slicebytetostring>
        next_IP = func.func_start_va + len(patch_data) + 5
        offset = next_IP - slicebytetostring_va
        offset = ~offset
        offset &= 0xFFFFFFFF
        offset += 1
        patch_data += b'\xe8' + struct.pack('<I', offset)

        patch_data += func.data[instruction_after_call_offset:]
        
        # append decrypted string right behind function
        patch_data += bytes(func.decrypted_string.encode('utf-8')) + b'\x00'
        
        func_len = func.func_end_va - func.func_start_va + 1
        
        patch_data += b'\xcc' * (func_len - len(patch_data))

        patch = Patch(patch_data, func.func_start_offset)
        
        self.patches.append(patch)