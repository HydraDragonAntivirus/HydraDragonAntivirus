//
// edrav2.edrdrv project
//
// Entropy calculation for ransomware detection
// Ported from Owlyshield minifilter
//
///
/// @file Shannon Entropy Calculator
///
/// @addtogroup edrdrv
/// @{
#pragma once

namespace cmd {
namespace entropy {

///
/// Calculate Shannon entropy of a buffer.
/// Entropy value ranges from 0.0 (all same bytes) to 8.0 (random data).
/// High entropy (>7.0) typically indicates encrypted or compressed data.
///
/// @param pBuffer - Pointer to data buffer.
/// @param nSize - Size of buffer in bytes.
/// @returns Shannon entropy value (0.0 to 8.0).
///
_Kernel_float_used_ 
DOUBLE calculateShannonEntropy(
	__in_bcount(nSize) PUCHAR pBuffer,
	__in size_t nSize
);

///
/// Check if entropy indicates potential encryption/ransomware.
///
/// @param entropy - Calculated entropy value.
/// @returns TRUE if entropy suggests encryption (>7.0), FALSE otherwise.
///
inline BOOLEAN isHighEntropy(DOUBLE entropy)
{
	return entropy > 7.0;
}

} // namespace entropy
} // namespace cmd
/// @}
