#pragma once

#include <fltKernel.h>

#include "common.h"

// ENTROPY_ONE_Q24 = 2^24.  Entropy range: [0, 8*ENTROPY_ONE_Q24].
// Convert to float: (double)result / (double)ENTROPY_ONE_Q24
constexpr ULONGLONG ENTROPY_ONE_Q24 = 1ULL << 24;

// Returns Shannon entropy in Q24 fixed-point (no floating point ops).
ULONGLONG shannonEntropyQ24(PUCHAR buffer, size_t size);

