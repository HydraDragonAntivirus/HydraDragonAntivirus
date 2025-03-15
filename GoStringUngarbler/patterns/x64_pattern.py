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

from abc import ABC
import re
from .base_pattern import GarblerPattern
PROLOGUE_PATTERN = rb'[\x49\x4D]\x3B[\S\s]{2}[\x0F\x76]'

# =====================================================================

# v1.21 -> v1.23
V21_V23_STACK_EPILOGUE_PATTERN = rb'\x48\x8D[\x5C\x9C][\S\s]{2,5}\xB9[\S\s]{4}[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48[\x81\x83][\S\s]{2,5}\x5D\xC3'
V21_V23_SPLIT_EPILOGUE_PATTERN = rb'\x31\xC0\x48\x89[\S\s]\x48\x89[\S\s][\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48[\x81\x83][\S\s]{2,5}\x5D\xC3'
V21_V23_SEED_EPILOGUE_PATTERN = rb'\x48\x8b[\S\s]\x48\x8b[\S\s]{2}\x31\xC0[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48[\x81\x83][\S\s]{2,5}\x5D\xC3'

# =====================================================================
# older 
OLD_STACK_EPILOGUE_PATTERN = rb'\x48\x8D[\x5C\x9C][\S\s]{2,5}\xB9[\S\s]{4}[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48\x8B[\S\s]{3,6}\x48[\x81\x83][\S\s]{2,5}\xC3' 
OLD_SPLIT_EPILOGUE_PATTERN = rb'\x31\xC0\x48\x89[\S\s]\x48\x89[\S\s][\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48\x8B[\S\s]{3,6}\x48[\x81\x83][\S\s]{2,5}\xC3'
OLD_SEED_EPILOGUE_PATTERN = rb'\x48\x8b[\S\s]\x48\x8b[\S\s]{2}\x31\xC0[\x66\x90]*[\x0F\x1F\x40\x00\x44]*\xE8[\S\s]{4}\x48\x8b[\S\s]{3,6}\x48[\x81\x83][\S\s]{2,5}\xC3'

# =====================================================================

class GarblerPatternX64(GarblerPattern):
    """
    Class for garble patterns of x64 Go binaries
    
    Attributes
    ----------
    go_version: str
        
        Detected go version of the garble-obfuscated sample (based on regex)
    """
    go_version: str
    
    def __init__(self, pe_data: bytes=None):
        """
        Constructor for GarblerPattern

        Args:
            pe_data (bytes, optional): Garble-obfuscated file data. Defaults to None.
        """
        super().__init__(pe_data)

        if re.search(V21_V23_STACK_EPILOGUE_PATTERN, pe_data) is not None and \
            re.search(V21_V23_SPLIT_EPILOGUE_PATTERN, pe_data) is not None and \
                re.search(V21_V23_SEED_EPILOGUE_PATTERN, pe_data) is not None:
                    self.stack_epilogue_pattern = re.compile(V21_V23_STACK_EPILOGUE_PATTERN)
                    self.split_epilogue_pattern = re.compile(V21_V23_SPLIT_EPILOGUE_PATTERN)
                    self.seed_epilogue_pattern = re.compile(V21_V23_SEED_EPILOGUE_PATTERN)
                    self.go_version = 'v1.21 -> v.23'
        else:
            self.stack_epilogue_pattern = re.compile(OLD_STACK_EPILOGUE_PATTERN)
            self.split_epilogue_pattern = re.compile(OLD_SPLIT_EPILOGUE_PATTERN)
            self.seed_epilogue_pattern = re.compile(OLD_SEED_EPILOGUE_PATTERN)
            
            self.go_version = '<= v1.20'

        self.prologue_pattern = re.compile(PROLOGUE_PATTERN)