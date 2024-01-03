/*
 * hexsimd.h - SIMD and SWAR accelerated hex formatting kernel
 *
 * Provides high-speed conversion of binary network packet slices into
 * formatted hexadecimal strings for interactive terminal displays.
 *
 * Author: filament contributors
 * License: MIT
 */

#ifndef FILAMENT_HEXSIMD_H
#define FILAMENT_HEXSIMD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Converts a raw byte buffer into hex characters.
 * Each input byte generates 2 output characters.
 * Destination buffer must have at least (src_len * 2) bytes available.
 */
void filament_bytes_to_hex(const uint8_t *src, size_t src_len, char *dst);

/*
 * Formats a single 16-byte line into canonical Wireshark-style hex dump:
 * "00000010  aa bb cc dd ee ff 00 11  22 33 44 55 66 77 88 99  |........"\"3DUfw..|\n"
 * Destination buffer must have at least 80 bytes available.
 * Returns number of characters written.
 */
size_t filament_format_hex_line(
    uint32_t offset,
    const uint8_t *data,
    size_t length,
    char *out_buf
);

#ifdef __cplusplus
}
#endif

#endif /* FILAMENT_HEXSIMD_H */
