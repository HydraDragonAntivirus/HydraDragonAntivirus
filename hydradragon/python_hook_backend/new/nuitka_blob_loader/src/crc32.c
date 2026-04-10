/*
 * crc32.c  --  Standard CRC-32/ISO-HDLC implementation.
 *
 * Polynomial: 0xEDB88320 (reflected form of 0x04C11DB7).
 * This matches what Nuitka uses via zlib crc32().
 */

#include <stdint.h>
#include <stddef.h>

/* Pre-computed lookup table (generated at first call). */
static uint32_t crc_table[256];
static int      crc_table_ready = 0;

static void build_crc_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xEDB88320u ^ (c >> 1);
            else
                c >>= 1;
        }
        crc_table[i] = c;
    }
    crc_table_ready = 1;
}

uint32_t calc_crc32(const uint8_t *data, size_t size) {
    if (!crc_table_ready)
        build_crc_table();

    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; i++) {
        uint8_t byte = data[i];
        crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}
