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

import re
from .base_pattern import GarblerPattern

PROLOGUE_PATTERN_X86 = rb'\x8B\x0D[\S\s]{4}\x64\x8B\x09\x8b\x09\x3B\x61\x08[\x0F\x76]'
# =====================================================================

# v1.21 -> v1.23

V21_V23_STACK_EPILOGUE_PATTERN_X86 = rb'\x89\x44\x24\x04\xC7\x44\x24\x08[\S\s]{4}\xE8[\S\s]{4}\x8B\x44\x24\x0c\x8B\x4C\x24\x10\x89\x44\x24[\S\s]\x89\x4C\x24[\S\s]\x83\xC4[\S\s]\xC3'

V21_V23_SPLIT_EPILOGUE_PATTERN_X86 = rb'\x89\x6C\x24\x04\x89\x74\x24\x08\xE8[\S\s]{4}\x8B\x44\x24\x0c\x8B\x4C\x24\x10\x89\x44\x24[\S\s]\x89\x4C\x24[\S\s]\x83\xC4[\S\s]\xC3'

V21_V23_SEED_EPILOGUE_PATTERN_X86 = rb'\x89\x4C\x24\x04\x89\x44\x24\x08\xE8[\S\s]{4}\x8B\x44\x24\x0c\x8B\x4C\x24\x10\x89\x44\x24[\S\s]\x89\x4C\x24[\S\s]\x83\xC4[\S\s]\xC3'

# =====================================================================

class GarblerPatternX86(GarblerPattern):
    """
    Class for garble patterns of x86 Go binaries
    """
    
    def __init__(self, pe_data: bytes=None):
        """
        Constructor for GarblerPattern

        Args:
            pe_data (bytes, optional): Garble-obfuscated file data. Defaults to None.
        """
        self.pe_data = pe_data

        self.stack_epilogue_pattern = re.compile(V21_V23_STACK_EPILOGUE_PATTERN_X86)
        self.split_epilogue_pattern = re.compile(V21_V23_SPLIT_EPILOGUE_PATTERN_X86)
        self.seed_epilogue_pattern = re.compile(V21_V23_SEED_EPILOGUE_PATTERN_X86)
        self.prologue_pattern = re.compile(PROLOGUE_PATTERN_X86)