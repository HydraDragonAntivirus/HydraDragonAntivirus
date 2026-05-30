
#include "ShanonEntropy.h"

static const ULONG       c_EntShift      = 24;
static const ULONGLONG   c_EntMaxQ24     = 8ULL * ENTROPY_ONE_Q24;
static const ULONGLONG   c_TwoOverLn2Q24 = 48408813ULL;

static ULONGLONG OwlyFloorLog2(ULONGLONG v)
{
    ULONGLONG r = 0;
    while (v > 1) { v >>= 1; r++; }
    return r;
}

static ULONGLONG OwlyMulQ24(ULONGLONG a, ULONGLONG b)
{
    return (a * b) >> c_EntShift;
}

static ULONGLONG OwlyLog2Q24(ULONGLONG v)
{
    if (v <= 1) return 0;

    ULONGLONG ip  = OwlyFloorLog2(v);
    ULONGLONG mQ24 = (ip >= c_EntShift)
                      ? (v >> (ip - c_EntShift))
                      : (v << (c_EntShift - ip));

    if (mQ24 < ENTROPY_ONE_Q24)         mQ24 = ENTROPY_ONE_Q24;
    if (mQ24 >= 2ULL * ENTROPY_ONE_Q24) mQ24 = 2ULL * ENTROPY_ONE_Q24 - 1;

    ULONGLONG z  = ((mQ24 - ENTROPY_ONE_Q24) * ENTROPY_ONE_Q24)
                 / (mQ24 + ENTROPY_ONE_Q24);
    ULONGLONG z2 = OwlyMulQ24(z, z);
    ULONGLONG zp = z;
    ULONGLONG s  = z;

    zp = OwlyMulQ24(zp, z2); s += zp / 3;
    zp = OwlyMulQ24(zp, z2); s += zp / 5;
    zp = OwlyMulQ24(zp, z2); s += zp / 7;
    zp = OwlyMulQ24(zp, z2); s += zp / 9;
    zp = OwlyMulQ24(zp, z2); s += zp / 11;
    zp = OwlyMulQ24(zp, z2); s += zp / 13;

    ULONGLONG frac = (s * c_TwoOverLn2Q24) >> c_EntShift;
    return (ip << c_EntShift) + frac;
}

ULONGLONG shannonEntropyQ24(PUCHAR buffer, size_t size)
{
    if (!buffer || size == 0) return 0;

    ULONGLONG bkt[256] = {};
    for (size_t i = 0; i < size; i++) bkt[buffer[i]]++;

    ULONGLONG slQ24 = OwlyLog2Q24((ULONGLONG)size);
    ULONGLONG wsum  = 0;
    for (ULONG i = 0; i < 256; i++)
        if (bkt[i]) wsum += bkt[i] * OwlyLog2Q24(bkt[i]);

    ULONGLONG avg  = wsum / (ULONGLONG)size;
    ULONGLONG eQ24 = (slQ24 > avg) ? (slQ24 - avg) : 0;
    if (eQ24 > c_EntMaxQ24) eQ24 = c_EntMaxQ24;
    return eQ24;
}
