
#include "ShanonEntropy.h"

constexpr ULONG MAX_BYTE_SIZE = 256;
constexpr ULONG ENTROPY_FIXED_SHIFT = 24;
constexpr ULONGLONG ENTROPY_ONE_Q24 = 1ULL << ENTROPY_FIXED_SHIFT;
constexpr ULONGLONG ENTROPY_MAX_Q24 = 8ULL * ENTROPY_ONE_Q24;
constexpr ULONGLONG ENTROPY_TWO_OVER_LN2_Q24 = 48408813ULL;

static ULONGLONG OwlyFloorLog2(ULONGLONG value)
{
    ULONGLONG result = 0;
    while (value > 1)
    {
        value >>= 1;
        result++;
    }
    return result;
}

static ULONGLONG OwlyMulQ24(ULONGLONG left, ULONGLONG right)
{
    return (left * right) >> ENTROPY_FIXED_SHIFT;
}

static ULONGLONG OwlyLog2Q24(ULONGLONG value)
{
    if (value <= 1)
    {
        return 0;
    }

    ULONGLONG integerPart = OwlyFloorLog2(value);
    ULONGLONG mantissaQ24;

    if (integerPart >= ENTROPY_FIXED_SHIFT)
    {
        mantissaQ24 = value >> (integerPart - ENTROPY_FIXED_SHIFT);
    }
    else
    {
        mantissaQ24 = value << (ENTROPY_FIXED_SHIFT - integerPart);
    }

    if (mantissaQ24 < ENTROPY_ONE_Q24)
    {
        mantissaQ24 = ENTROPY_ONE_Q24;
    }

    if (mantissaQ24 >= (2ULL * ENTROPY_ONE_Q24))
    {
        mantissaQ24 = (2ULL * ENTROPY_ONE_Q24) - 1;
    }

    ULONGLONG zQ24 =
        ((mantissaQ24 - ENTROPY_ONE_Q24) * ENTROPY_ONE_Q24) /
        (mantissaQ24 + ENTROPY_ONE_Q24);
    ULONGLONG zSquaredQ24 = OwlyMulQ24(zQ24, zQ24);
    ULONGLONG zPowerQ24 = zQ24;
    ULONGLONG seriesQ24 = zQ24;

    zPowerQ24 = OwlyMulQ24(zPowerQ24, zSquaredQ24);
    seriesQ24 += zPowerQ24 / 3;
    zPowerQ24 = OwlyMulQ24(zPowerQ24, zSquaredQ24);
    seriesQ24 += zPowerQ24 / 5;
    zPowerQ24 = OwlyMulQ24(zPowerQ24, zSquaredQ24);
    seriesQ24 += zPowerQ24 / 7;
    zPowerQ24 = OwlyMulQ24(zPowerQ24, zSquaredQ24);
    seriesQ24 += zPowerQ24 / 9;
    zPowerQ24 = OwlyMulQ24(zPowerQ24, zSquaredQ24);
    seriesQ24 += zPowerQ24 / 11;
    zPowerQ24 = OwlyMulQ24(zPowerQ24, zSquaredQ24);
    seriesQ24 += zPowerQ24 / 13;

    ULONGLONG fractionalPartQ24 =
        (seriesQ24 * ENTROPY_TWO_OVER_LN2_Q24) >> ENTROPY_FIXED_SHIFT;

    return (integerPart << ENTROPY_FIXED_SHIFT) + fractionalPartQ24;
}

_Kernel_float_used_ DOUBLE shannonEntropy(PUCHAR buffer, size_t size)
{
#if IS_DEBUG_IRP
    DbgPrint("!!! FSfilter: Calc entropy started\n");
#endif

    if (buffer == NULL || size == 0)
    {
        return 0.0;
    }

    DOUBLE entropy = 0.0;
    ULONGLONG bucketByteVals[MAX_BYTE_SIZE] = {};
    for (size_t i = 0; i < size; i++)
    {
        bucketByteVals[buffer[i]]++;
    }

    ULONGLONG sizeLogQ24 = OwlyLog2Q24((ULONGLONG)size);
    ULONGLONG weightedLogSumQ24 = 0;

    for (ULONG i = 0; i < MAX_BYTE_SIZE; i++)
    {
        if (bucketByteVals[i] != 0)
        {
            weightedLogSumQ24 += bucketByteVals[i] * OwlyLog2Q24(bucketByteVals[i]);
        }
    }

    ULONGLONG averageLogQ24 = weightedLogSumQ24 / (ULONGLONG)size;
    ULONGLONG entropyQ24 = sizeLogQ24 > averageLogQ24 ? sizeLogQ24 - averageLogQ24 : 0;
    if (entropyQ24 > ENTROPY_MAX_Q24)
    {
        entropyQ24 = ENTROPY_MAX_Q24;
    }

    entropy = (DOUBLE)entropyQ24 / (DOUBLE)ENTROPY_ONE_Q24;
    return entropy;
}
