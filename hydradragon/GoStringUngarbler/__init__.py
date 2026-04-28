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

"""
GoStringUngarbler API Wrapper
~~~~~~~~~~~~~~~~~~~

A basic wrapper for the GoStringUngarbler API.

"""

from .patchers import Function, Patch, Patcher, PatcherX64, PatcherX86
from .patterns import (
    GarblerPattern,
    GarblerPatternX64,
    GarblerPatternX86,
    SEED_STRING_DECRYPTION,
    SPLIT_STRING_DECRYPTION,
    STACK_STRING_DECRYPTION,
)
from .ungarblers import GoStringUngarbler, GoStringUngarblerX64, GoStringUngarblerX86

__all__ = [
    "Function",
    "Patch",
    "Patcher",
    "PatcherX64",
    "PatcherX86",
    "GarblerPattern",
    "GarblerPatternX64",
    "GarblerPatternX86",
    "SEED_STRING_DECRYPTION",
    "SPLIT_STRING_DECRYPTION",
    "STACK_STRING_DECRYPTION",
    "GoStringUngarbler",
    "GoStringUngarblerX64",
    "GoStringUngarblerX86",
]
