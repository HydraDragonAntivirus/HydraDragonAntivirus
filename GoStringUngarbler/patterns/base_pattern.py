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

STACK_STRING_DECRYPTION = 1
SPLIT_STRING_DECRYPTION = 2
SEED_STRING_DECRYPTION = 3

class GarblerPattern(ABC):
    """
    Base class for garble patterns
    
    Attributes
    ----------
    go_version: str
        
        Detected go version of the garble-obfuscated sample (based on regex)

    pe_data: bytes
    
        File bytes data
        
    stack_epilogue_pattern: re.Pattern
    
        Regex bytes pattern for the stack string decoding function's epilogue to use
        
    split_epilogue_pattern: re.Pattern
    
        Regex bytes pattern for the split string decoding function's epilogue to use
        
    seed_epilogue_pattern: re.Pattern
    
        Regex bytes pattern for the seed string decoding function's epilogue to use
        
    prologue_pattern: re.Pattern
    
        Regex bytes pattern for the decoding function's prologue to use     
    """
    go_version: str
    pe_data: bytes
    
    stack_epilogue_pattern: re.Pattern
    split_epilogue_pattern: re.Pattern
    seed_epilogue_pattern: re.Pattern
    
    prologue_pattern: re.Pattern
    
    def __init__(self, pe_data: bytes=None):
        """
        Constructor for GarblerPattern

        Args:
            pe_data (bytes, optional): Garble-obfuscated file data. Defaults to None.
        """
        self.pe_data = pe_data
        
    def get_epilogue_pattern(self, decrypt_type: int) -> re.Pattern:
        """
        Get string decrypt function's epilogue regex pattern depending on the decryption type
        Args:
            decrypt_type (int): decryption type (STACK_STRING_DECRYPTION, SPLIT_STRING_DECRYPTION, or SEED_STRING_DECRYPTION)

        Raises:
            Exception: Invalid decryption type

        Returns:
            re.Pattern: epilogue regex pattern for that type
        """
        if decrypt_type == STACK_STRING_DECRYPTION:
            return self.stack_epilogue_pattern
        elif decrypt_type == SPLIT_STRING_DECRYPTION:
            return self.split_epilogue_pattern
        elif decrypt_type == SEED_STRING_DECRYPTION:
            return self.seed_epilogue_pattern
        else:
            raise Exception('Unknown decryption type')