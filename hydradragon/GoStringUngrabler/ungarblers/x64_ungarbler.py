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

import struct
from typing import List
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
import logging as logger
from GoStringUngarbler.patchers import Function
import lief
from .base_ungarbler import GoStringUngarbler
from GoStringUngarbler.patterns import STACK_STRING_DECRYPTION, SPLIT_STRING_DECRYPTION, SEED_STRING_DECRYPTION

class GoStringUngarblerX64(GoStringUngarbler):
    """
    Class for the x64 string ungarbler engine
    """
    
    def __init__(self, lief_binary: lief.Binary, binary_data: bytes):
        """
        Constructors for the string ungarbler

        Args:
            lief_binary (lief.Binary): Binary object of the PE
            
            binary_data (bytes): Content of the input executable
        """
        super().__init__(lief_binary, binary_data)
        self.unicorn_emu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.unicorn_emu.detail = True
        
        # initialize binary in memory
        # load PE's sections in 
        if self.lief_binary.format == lief.Binary.FORMATS.PE:
            section_alignment = self.lief_binary.optional_header.section_alignment
            for section in self.lief_binary.sections:
                section_va = self.mem_align(self.lief_binary.imagebase + section.virtual_address, section_alignment)
                section_mem_perm = 0
                
                if section.characteristics & 0x20000000: # IMAGE_SCN_MEM_EXECUTE
                    section_mem_perm |= UC_PROT_EXEC
                if section.characteristics & 0x40000000: # IMAGE_SCN_MEM_READ
                    section_mem_perm |= UC_PROT_READ
                if section.characteristics & 0x80000000: # IMAGE_SCN_MEM_WRITE
                    section_mem_perm |= UC_PROT_WRITE
                section_aligned_size = self.mem_align(section.virtual_size, section_alignment)
                
                self.unicorn_emu.mem_map(section_va, section_aligned_size, section_mem_perm)
                self.unicorn_emu.mem_write(section_va, bytes(section.content))
        elif self.lief_binary.format == lief.Binary.FORMATS.ELF:
            self.unicorn_emu.mem_map(self.lief_binary.imagebase, self.lief_binary.virtual_size)
            for segment in self.lief_binary.segments:
                self.unicorn_emu.mem_write(segment.virtual_address, bytes(segment.content))
        else:
            raise Exception('Non-supported file type')
        
        # map the stack into memory & clear it out
        self.unicorn_emu.mem_map(self.stack_base, self.stack_size)
        
        # map the heap into memory & clear it out
        self.unicorn_emu.mem_map(self.heap_base, self.heap_size)
        
        # throw initial RSP and RBP into middle of the stack 
        self.reset_stack_and_heap()
        
        # initialize capstone disassembler in 64-bit mode
        self.capstone = Cs(CS_ARCH_X86, CS_MODE_64)
        self.capstone.detail = True
    
    def instruction_hook_seed(self, uc, address, size, user_data) -> None:
        """
        Hook function to handle garble's seed decryption

        Args:
            uc (Uc): unicorn emulator
            address (int): Adress of instruction
            size (int): Size of instruction
            user_data (object): User data
        """
        
        instruction = next(self.capstone.disasm(uc.mem_read(address, size), address))
        
        # Very noisy
        # logger.debug("0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))
            
        if instruction.mnemonic == 'call':
            if self.runtime_newobject_call_count < 4:
                heap_allocated_mem = self.heap_alloc(0x100)
                self.unicorn_emu.reg_write(UC_X86_REG_RAX, heap_allocated_mem)
                # skip all 4 calls. We just manually do a heap alloc for each
                self.unicorn_emu.reg_write(UC_X86_REG_RIP, instruction.address + 5)
                
                if self.runtime_newobject_call_count == 1:
                    # second buffer allocated will contain the pointer to the string + its length
                    self.call_result_struct_ptr = heap_allocated_mem
                self.runtime_newobject_call_count += 1
            else:
                # for any other calls that are not call <register>
                # NOTE: call <register> is a call to the seed update subroutine from the obfuscator
                if instruction.op_str[0] != 'r':
                    # call    runtime_growslice 
                    # should just return the pointer to the old buffer
                    self.unicorn_emu.reg_write(UC_X86_REG_RAX, self.heap_base + self.heap_alloc_offset)
                    self.unicorn_emu.reg_write(UC_X86_REG_RCX, 8)
                    self.unicorn_emu.reg_write(UC_X86_REG_RIP, instruction.address + 5)
    
    def reset_stack_and_heap(self):
        """Reset stack and base pointers to the middle of stack
        
        Zero out stack and heap
        """
        
        if self.unicorn_emu is None:
            logger.debug('Unicorn emulator is not initialized')
            return
        
        self.unicorn_emu.reg_write(UC_X86_REG_RSP, self.stack_base + self.stack_size // 2)
        self.unicorn_emu.reg_write(UC_X86_REG_RBP, self.stack_base + self.stack_size // 2)
        
        # R14 is set to stack pointer for stack check in each subroutine 
        self.unicorn_emu.reg_write(UC_X86_REG_R14, self.stack_base + self.stack_size // 2)
        
        # zero out stack and heap
        self.unicorn_emu.mem_write(self.stack_base, b'\x00' * self.stack_size)
        self.unicorn_emu.mem_write(self.heap_base, b'\x00' * self.heap_size)
        
        self.heap_alloc_offset = 0
    
    def instruction_hook(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        """
        Hook function to debug and print executed instructions by unicorn engine

        Args:
            uc (Uc): unicorn emulator
            address (int): Adress of instruction
            size (int): Size of instruction
            user_data (object): User data
        """
        
        # Get the current instruction
        instruction = next(self.capstone.disasm(uc.mem_read(address, size), address))
        
        if instruction.mnemonic == 'ret':
            # not supposed to ret since we don't emulate any subroutine 
            # or reach the ret insn of the decrypting subroutine
            raise Exception("Not supposed to return")
        
        if instruction.mnemonic == 'call':
            # runtime.growslice here. No need for multiple allocation
            self.unicorn_emu.reg_write(UC_X86_REG_RAX, self.heap_base + self.heap_alloc_offset)
            
            # restore RBX and RCX
            self.unicorn_emu.reg_write(UC_X86_REG_RBX, self.unicorn_emu.reg_read(UC_X86_REG_RCX))
            self.unicorn_emu.reg_write(UC_X86_REG_RCX, self.unicorn_emu.reg_read(UC_X86_REG_RSI))
            
            # skip call since we already emulate
            self.unicorn_emu.reg_write(UC_X86_REG_RIP, instruction.address + 5)
        
        # Very noisy
        # logger.debug("0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))
        
    def emulate(self, func: Function) -> str:
        """
        Emulate a function from function start to stop address (call runtime_slicebytetostring)

        Extract the decrypted string
        Args:
            func (Function): Function to emulate

        Returns:
            str: Decrypted string
        """
        
        # emulate setup
        self.reset_stack_and_heap()
        
        # set hook function 
        if func.type == SEED_STRING_DECRYPTION:
            hook_func = self.instruction_hook_seed
            self.runtime_newobject_call_count = 0
            self.call_result_struct_ptr = 0x0
        else:
            hook_func = self.instruction_hook
        
        # hooking
        hook_handle = self.unicorn_emu.hook_add(UC_HOOK_CODE, hook_func)
        
        # start emulate
        try:
            self.unicorn_emu.emu_start(func.func_start_emu_va, func.emu_stop_va, UC_SECOND_SCALE * self.MAX_EMU_TIME, 0)
        except Exception as e:
            self.unicorn_emu.hook_del(hook_handle)
            raise Exception(e)
        
        # get string pointer and size
        if func.type == SEED_STRING_DECRYPTION:
            decrypted_str_ptr = struct.unpack('<q', self.unicorn_emu.mem_read(self.call_result_struct_ptr, 8))[0]
            decrypted_str_size = struct.unpack('<q', self.unicorn_emu.mem_read(self.call_result_struct_ptr + 8, 8))[0]
        else:    
            decrypted_str_ptr = self.unicorn_emu.reg_read(UC_X86_REG_RBX)
            decrypted_str_size = self.unicorn_emu.reg_read(UC_X86_REG_RCX)

        # delete hook
        self.unicorn_emu.hook_del(hook_handle)
        
        # extract strings
        if decrypted_str_ptr == 0:
            return ''
        
        decrypted_str_bytes = self.unicorn_emu.mem_read(decrypted_str_ptr, decrypted_str_size)
        decrypted_str_bytes = decrypted_str_bytes.replace(b'\x00', b'')
        decrypted_string = decrypted_str_bytes.decode('utf-8')

        # Check if the character is a printable character or a specific control character
        for character in decrypted_string:
            if not (
                # Printable ASCII characters
                (32 <= ord(character) <= 126) or 
                # Specific whitespace and control characters we want to allow
                character in '\r\n\t'
            ):
                raise Exception('Contain not readable character')
        
        return decrypted_string