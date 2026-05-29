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
#include "common.h"
#include "entropy.h"

namespace cmd {
namespace entropy {

// Constants for fixed-point arithmetic (Q24 format)
static constexpr ULONG c_nMaxByteSize = 256;
static constexpr ULONG c_nEntropyFixedShift = 24;
static constexpr ULONGLONG c_nEntropyOneQ24 = 1ULL << c_nEntropyFixedShift;
static constexpr ULONGLONG c_nEntropyMaxQ24 = 8ULL * c_nEntropyOneQ24;
static constexpr ULONGLONG c_nEntropyTwoOverLn2Q24 = 48408813ULL;

///
/// Calculate floor(log2(value)) using bit shifting.
///
/// @param value - Input value.
/// @returns Floor of log2(value).
///
static ULONGLONG floorLog2(ULONGLONG value)
{
	ULONGLONG result = 0;
	while (value > 1)
	{
		value >>= 1;
		result++;
	}
	return result;
}

///
/// Multiply two Q24 fixed-point numbers.
///
/// @param left - Left operand in Q24 format.
/// @param right - Right operand in Q24 format.
/// @returns Product in Q24 format.
///
static ULONGLONG mulQ24(ULONGLONG left, ULONGLONG right)
{
	return (left * right) >> c_nEntropyFixedShift;
}

///
/// Calculate log2(value) in Q24 fixed-point format.
/// Uses Taylor series approximation for fractional part.
///
/// @param value - Input value.
/// @returns log2(value) in Q24 format.
///
static ULONGLONG log2Q24(ULONGLONG value)
{
	if (value <= 1)
	{
		return 0;
	}

	// Integer part of log2
	ULONGLONG integerPart = floorLog2(value);
	ULONGLONG mantissaQ24;

	// Normalize mantissa to [1.0, 2.0) range in Q24 format
	if (integerPart >= c_nEntropyFixedShift)
	{
		mantissaQ24 = value >> (integerPart - c_nEntropyFixedShift);
	}
	else
	{
		mantissaQ24 = value << (c_nEntropyFixedShift - integerPart);
	}

	// Clamp mantissa to valid range
	if (mantissaQ24 < c_nEntropyOneQ24)
	{
		mantissaQ24 = c_nEntropyOneQ24;
	}

	if (mantissaQ24 >= (2ULL * c_nEntropyOneQ24))
	{
		mantissaQ24 = (2ULL * c_nEntropyOneQ24) - 1;
	}

	// Calculate fractional part using Taylor series
	// ln(x) = 2 * (z + z^3/3 + z^5/5 + ...) where z = (x-1)/(x+1)
	ULONGLONG zQ24 =
		((mantissaQ24 - c_nEntropyOneQ24) * c_nEntropyOneQ24) /
		(mantissaQ24 + c_nEntropyOneQ24);
	ULONGLONG zSquaredQ24 = mulQ24(zQ24, zQ24);
	ULONGLONG zPowerQ24 = zQ24;
	ULONGLONG seriesQ24 = zQ24;

	// Taylor series terms
	zPowerQ24 = mulQ24(zPowerQ24, zSquaredQ24);
	seriesQ24 += zPowerQ24 / 3;
	zPowerQ24 = mulQ24(zPowerQ24, zSquaredQ24);
	seriesQ24 += zPowerQ24 / 5;
	zPowerQ24 = mulQ24(zPowerQ24, zSquaredQ24);
	seriesQ24 += zPowerQ24 / 7;
	zPowerQ24 = mulQ24(zPowerQ24, zSquaredQ24);
	seriesQ24 += zPowerQ24 / 9;
	zPowerQ24 = mulQ24(zPowerQ24, zSquaredQ24);
	seriesQ24 += zPowerQ24 / 11;
	zPowerQ24 = mulQ24(zPowerQ24, zSquaredQ24);
	seriesQ24 += zPowerQ24 / 13;

	// Convert ln to log2: log2(x) = ln(x) / ln(2)
	ULONGLONG fractionalPartQ24 =
		(seriesQ24 * c_nEntropyTwoOverLn2Q24) >> c_nEntropyFixedShift;

	return (integerPart << c_nEntropyFixedShift) + fractionalPartQ24;
}

///
/// Calculate Shannon entropy of a buffer.
///
_Kernel_float_used_ 
DOUBLE calculateShannonEntropy(
	__in_bcount(nSize) PUCHAR pBuffer,
	__in size_t nSize
)
{
	if (pBuffer == nullptr || nSize == 0)
	{
		return 0.0;
	}

	DOUBLE entropy = 0.0;
	ULONGLONG bucketByteVals[c_nMaxByteSize] = {};

	// Count frequency of each byte value
	for (size_t i = 0; i < nSize; i++)
	{
		bucketByteVals[pBuffer[i]]++;
	}

	// Calculate Shannon entropy using fixed-point arithmetic
	// H(X) = -Σ p(x) * log2(p(x)) = log2(n) - (1/n) * Σ count(x) * log2(count(x))
	ULONGLONG sizeLogQ24 = log2Q24((ULONGLONG)nSize);
	ULONGLONG weightedLogSumQ24 = 0;

	for (ULONG i = 0; i < c_nMaxByteSize; i++)
	{
		if (bucketByteVals[i] != 0)
		{
			weightedLogSumQ24 += bucketByteVals[i] * log2Q24(bucketByteVals[i]);
		}
	}

	ULONGLONG averageLogQ24 = weightedLogSumQ24 / (ULONGLONG)nSize;
	ULONGLONG entropyQ24 = sizeLogQ24 > averageLogQ24 ? sizeLogQ24 - averageLogQ24 : 0;

	// Clamp to maximum entropy (8.0 bits)
	if (entropyQ24 > c_nEntropyMaxQ24)
	{
		entropyQ24 = c_nEntropyMaxQ24;
	}

	// Convert from Q24 fixed-point to floating-point
	entropy = (DOUBLE)entropyQ24 / (DOUBLE)c_nEntropyOneQ24;
	return entropy;
}

} // namespace entropy
} // namespace cmd
/// @}
