/*
 * VersionDetector.c
 *
 * Clean reconstruction of View8's VersionDetector.exe from the provided
 * Hex-Rays decompiler output.
 *
 * Behavior:
 *   VersionDetector.exe -h <major.minor.build.patch>
 *      Prints the V8 cached-data version hash as lowercase hex.
 *
 *   VersionDetector.exe -d <hash>
 *      Brute-forces and prints the matching V8 version in the range:
 *        major: 1..29
 *        minor: 1..49
 *        build: 1..399
 *        patch: 1..299
 *
 *   VersionDetector.exe -f <file>
 *      Reads 4 bytes at offset 4 from a V8 cached-data file, then decodes
 *      that hash using the same brute-force range.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t mix32(uint32_t value)
{
    /*
     * Reconstructed from sub_1400010E0's repeated per-component mixer:
     *
     *   x = ~x + (x << 15)
     *   x ^= x >> 12
     *   x *= 5
     *   x ^= x >> 4
     *   x *= 2057
     *   x ^= x >> 16
     */
    uint32_t x = ~value + (value << 15);
    x ^= x >> 12;
    x *= 5u;
    x ^= x >> 4;
    x *= 2057u;
    x ^= x >> 16;
    return x;
}

static uint64_t avalanche64(uint32_t value)
{
    const uint64_t m = 0xC6A4A7935BD1E995ULL;
    uint64_t x = m * (uint64_t)value;
    return m * (x ^ (x >> 47));
}

static uint32_t v8_version_hash(uint32_t major, uint32_t minor, uint32_t build, uint32_t patch)
{
    /*
     * Clean equivalent of sub_1400010E0().
     *
     * The decompiled function combines the four mixed version components
     * using a MurmurHash-style 64-bit multiplier and returns the low 32 bits,
     * matching the original function's int return in main().
     */
    const uint64_t m = 0xC6A4A7935BD1E995ULL;
    uint64_t h = 0x35A98F4D286A90B9ULL * avalanche64(mix32(patch));

    h ^= avalanche64(mix32(build));
    h = m * (h ^ (h >> 47));

    h ^= avalanche64(mix32(minor));
    h = m * (h ^ (h >> 47));

    h ^= avalanche64(mix32(major));
    h = m * (h ^ (h >> 47));

    return (uint32_t)h;
}

static int decode_hash(uint32_t hash)
{
    /*
     * Reconstructed from sub_140001220():
     *   major < 0x1E, minor < 0x32, build < 0x190, patch < 0x12C
     * with all loops starting at 1.
     */
    for (uint32_t major = 1; major < 30; ++major) {
        for (uint32_t minor = 1; minor < 50; ++minor) {
            for (uint32_t build = 1; build < 400; ++build) {
                for (uint32_t patch = 1; patch < 300; ++patch) {
                    if (v8_version_hash(major, minor, build, patch) == hash) {
                        printf("%u.%u.%u.%u\n", major, minor, build, patch);
                        return 0;
                    }
                }
            }
        }
    }

    printf("Error can't find version %x\n", hash);
    return 1;
}

static int decode_file_hash(const char *file_name)
{
    FILE *fp = fopen(file_name, "rb");
    if (fp == NULL) {
        perror("Error opening file");
        return 0; /* Matches the original binary's behavior. */
    }

    if (fseek(fp, 4, SEEK_SET) != 0) {
        perror("Error seeking in file");
        fclose(fp);
        return 0; /* Matches the original binary's behavior. */
    }

    uint32_t hash = 0;
    if (fread(&hash, sizeof(hash), 1, fp) != 1) {
        perror("Error reading from file");
        fclose(fp);
        return 0; /* Matches the original binary's behavior. */
    }

    fclose(fp);
    return decode_hash(hash);
}

static void print_usage(const char *program)
{
    printf("Usage: %s <-h|-d|-f> <version|hash|file>\n", program);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-h") == 0) {
        unsigned int major = 0;
        unsigned int minor = 0;
        unsigned int build = 0;
        unsigned int patch = 0;

        if (sscanf(argv[2], "%u.%u.%u.%u", &major, &minor, &build, &patch) == 4) {
            printf("%x\n", v8_version_hash(major, minor, build, patch));
            return 0;
        }

        printf("Invalid version format. Expected format: x.x.x.x\n");
        return 1;
    }

    if (strcmp(argv[1], "-d") == 0) {
        uint32_t hash = 0;
        if (sscanf(argv[2], "%x", &hash) != 1) {
            printf("Invalid hash format. Expected hexadecimal hash.\n");
            return 1;
        }
        return decode_hash(hash);
    }

    if (strcmp(argv[1], "-f") == 0) {
        return decode_file_hash(argv[2]);
    }

    /*
     * The original checks argv[1][1], so any flag with second character h/d/f
     * works. This cleaned version intentionally accepts only exact flags.
     */
    printf("Invalid flag. Use -h for hashing, -d for decoding hash, and -f for decoding file hash.\n");
    return 1;
}
