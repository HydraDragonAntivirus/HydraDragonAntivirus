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
import re
from typing import List
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
import logging as logger
from GoStringUngarbler.patchers import Function
from GoStringUngarbler.patterns import GarblerPattern, STACK_STRING_DECRYPTION, SPLIT_STRING_DECRYPTION, SEED_STRING_DECRYPTION
import lief

class GoStringUngarbler(ABC):
    """
    Class for the base string ungarbler engine
    
    Attributes
    ----------
    unicorn_emu: Uc 
        
        Unicorn emulator

    stack_base: int 
            
        Emulator's stack base address (default: 0xc0000000)
        
    stack_size: int 
            
        Emulator's stack size (default: 0x100000)
        
    heap_base: int 
            
        Emulator's heap base address (default: 0xd0000000)
        
    heap_size: int 
            
        Emulator's stack size (default: 0x10000)
        
    heap_alloc_offset: int 
            
        Offset from the heap base to allocate new memory
    
    lief_binary: lief.Binary
    
        Lief binary of the input file
    
    binary_data: bytes
            
        Content of the input executable
        
    capstone: Cs
            
        Capstone disassembler
        
    decrypt_func_list: List[Function]

        List of Function objects, each representing a string decrypting function
        
    runtime_newobject_call_count: int

        Call count to keep track of how many call instructions to skip (For pattern.CALL_STRING_DECRYPTION)
    
    call_result_struct_ptr: int
    
        Pointer to a memory region of the stack that contains the pointer to the decrypted string & its length (For pattern.CALL_STRING_DECRYPTION)
    
    stack_func_count: int
    
        Number of stack string decrypt functions encountered
    
    split_func_count: int
    
        Number of split string decrypt functions encountered
    
    seed_func_count: int
    
        Number of seed string decrypt functions encountered
    
    MAX_EMU_TIME: int
    
        Maximum emulating time we accept (Default: 5 seconds)
    """
    unicorn_emu: Uc
    stack_base: int = 0xc0000000
    stack_size: int = 0x100000
    heap_base: int =  0xd0000000
    heap_size: int =  0x10000
    heap_alloc_offset: int = 0x0
    lief_binary: lief.Binary = None
    
    binary_data: bytes
    capstone: Cs
    decrypt_func_list: List[Function]
    runtime_newobject_call_count: int = 0x0
    call_result_struct_ptr: int = 0x0
    stack_func_count: int = 0x0
    split_func_count: int = 0x0
    seed_func_count: int = 0x0
    
    MAX_EMU_TIME: int = 5 
    
    def __init__(self, lief_binary: lief.Binary, binary_data: bytes):
        """
        Constructors for the string ungarbler

        Args:
            lief_binary (lief.Binary): Binary object of the PE
            
            binary_data (bytes): Content of the input executable
        """
        
        self.lief_binary = lief_binary
        self.binary_data = binary_data
        
        # initialize string decryption function list
        self.decrypt_func_list = []
    
    @abstractmethod
    def reset_stack_and_heap(self):
        """Reset stack and base pointers to the middle of stack
        
        Zero out stack and heap
        """
        
        pass
    
    def mem_align(self, address: int, section_alignment: int) -> int:
        """
        Aligns the given address to the nearest multiple of alignment.
        
        Args:
            address (int): address to align
            
            section_alignment (int): section alignment
            
        Returns:
            int: aligned address
        """
        return ((address + section_alignment - 1) // section_alignment) * section_alignment

    def heap_alloc(self, size: int) -> int:
        """
        Heap allocate

        Args:
            size (int): size to allocate

        Returns:
            int: pointer to the allocated memory on the heap
        """
        allocated_mem_ptr = self.heap_base + self.heap_alloc_offset
        
        if allocated_mem_ptr + size > self.heap_base + self.heap_size:
            logger.debug('Run out of heap space')
            return -1
        
        self.heap_alloc_offset += size
        
        return allocated_mem_ptr

    @abstractmethod
    def instruction_hook_seed(self, uc, address, size, user_data) -> None:
        """
        Hook function to handle garble's seed decryption

        Args:
            uc (Uc): unicorn emulator
            address (int): Adress of instruction
            size (int): Size of instruction
            user_data (object): User data
        """
        pass
        
    @abstractmethod
    def instruction_hook(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        """
        Hook function to debug and print executed instructions by unicorn engine

        Args:
            uc (Uc): unicorn emulator
            address (int): Adress of instruction
            size (int): Size of instruction
            user_data (object): User data
        """
        pass
    
    def find_string_decryption_routine(self, decrypt_type: int, garble_pattern: GarblerPattern):
        """
        Function to find all decryption routine

        Args:
            decrypt_type (int): Type of string decryption routine to find
            
                STACK_STRING_DECRYPTION, SPLIT_STRING_DECRYPTION, or SEED_STRING_DECRYPTION
            
            garble_pattern (pattern.GarblerPattern): garbler pattern object
        """
        
        # get .text section virtual address & data
        text_section_va = 0
        text_section_data = None
        text_section_offset = 0
        for section in self.lief_binary.sections:
            if section.name != '.text':
                continue
            if self.lief_binary.format == lief.Binary.FORMATS.PE:
                text_section_va = self.lief_binary.imagebase + section.virtual_address
            elif self.lief_binary.format == lief.Binary.FORMATS.ELF:
                text_section_va = section.virtual_address
            else:
                raise Exception('Non-supported file type')
            text_section_data = bytes(section.content)
            text_section_offset = section.offset
            break
        
        if text_section_data is None:
            return None
        
        # set the appropriate function's epilogue pattern based on the type
        string_decrypt_epilogue_pattern = garble_pattern.get_epilogue_pattern(decrypt_type)
        
        last_func_end_offset = 0
        
        for match in string_decrypt_epilogue_pattern.finditer(text_section_data):
            # locate each function epilogue through regex
            func_end_offset = match.end()
            
            # locate current function's prologue from the last function end to the current function end
            prologue_matches = garble_pattern.prologue_pattern.findall(
                text_section_data, pos=last_func_end_offset, endpos=func_end_offset)
            
            if len(prologue_matches) == 0:
                logger.debug('[+] Error finding function prologue')
                continue
            
            # function's prologue is the last regex match before the epilogue
            func_prologue_data = prologue_matches[-1]
            
            # relative from text section
            func_start_relative_offset = text_section_data.rfind(
                func_prologue_data, last_func_end_offset, func_end_offset)
            
            # get virtual address of the function
            func_start_va = func_start_relative_offset + text_section_va
            
            # get function data
            func_data = text_section_data[func_start_relative_offset:func_end_offset]
            
            # find virtual address to stop emulation (at call runtime_slicebytetostring)
            
            epilogue_pattern = string_decrypt_epilogue_pattern.pattern
            epilogue_pattern = epilogue_pattern[:epilogue_pattern.find(rb'\xE8[\S\s]')]
            
            match = re.search(epilogue_pattern, func_data)
            
            if match is None:
                raise Exception('Can not find epilogue')
            
            slicebytetostring_call_offset = match.end()
            
            emu_stop_va = func_start_va + slicebytetostring_call_offset
            
            # we want to skip the stack cmp & jmp instruction of epilogue during emulation
            #   Epilogue type 1:
            #       49 3B 66 10         cmp     rsp, [r14+10h]
            #       76 70               jbe     short loc_46F6D6
            #
            #   Epilogue type 2:
            #       49 3B 66 10         cmp     rsp, [r14+10h]
            #       0F 86 94 03 00 00   jbe     loc_552DFE
            
            if func_prologue_data[-1] == 0x76:
                # epilogue type 1
                func_start_emu_va = func_start_va + len(func_prologue_data) + 1
            elif func_prologue_data[-1] == 0xf:
                # epilogue type 2
                func_start_emu_va = func_start_va + len(func_prologue_data) + 5

            # update last function end offset
            last_func_end_offset = func_end_offset

            # end at address of the retn instruction
            func_end_va = func_end_offset + text_section_va - 1
            
            # offset to patch the new string resolving subroutine in
            func_start_offset = text_section_offset + func_start_relative_offset
            
            # append the function into the list
            self.decrypt_func_list.append(Function(func_data, func_start_offset, func_start_va, func_start_emu_va, func_end_va, emu_stop_va, decrypt_type))     

            # Update counter
            if decrypt_type == STACK_STRING_DECRYPTION:
                self.stack_func_count += 1
            elif decrypt_type == SPLIT_STRING_DECRYPTION:
                self.split_func_count += 1
            elif decrypt_type == SEED_STRING_DECRYPTION:
                self.seed_func_count += 1
            else:
                raise Exception('Wrong decryption type')
    
    @abstractmethod
    def emulate(self, func: Function) -> str:
        """
        Emulate a function from function start to stop address (call runtime_slicebytetostring)

        Extract the decrypted string
        Args:
            func (Function): Function to emulate

        Returns:
            str: Decrypted string
        """
        
        pass