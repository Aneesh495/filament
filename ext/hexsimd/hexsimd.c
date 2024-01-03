/*
 * hexsimd.c - SIMD and SWAR accelerated hex formatting kernel
 *
 * Implements high-throughput binary-to-hex conversion using SIMD table
 * lookups (ARM NEON vtbl1 on Apple Silicon / ARM64, and portable SWAR).
 *
 * Author: filament contributors
 * License: MIT
 */

#include "hexsimd.h"
#include <stdio.h>

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#endif

static const char hex_chars[16] = "0123456789abcdef";

void filament_bytes_to_hex(const uint8_t *src, size_t src_len, char *dst) {
    size_t i = 0;

#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    /* NEON vectorized 8-byte chunk loop -> produces 16 hex characters */
    const uint8x8_t hex_table = vld1_u8((const uint8_t *)hex_chars);
    const uint8x8_t mask_low = vdup_n_u8(0x0F);

    while (i + 8 <= src_len) {
        uint8x8_t in = vld1_u8(src + i);

        /* High nibbles */
        uint8x8_t hi = vshr_n_u8(in, 4);
        /* Low nibbles */
        uint8x8_t lo = vand_u8(in, mask_low);

        uint8x8_t hex_hi = vqtbl1_u8(hex_table, hi);
        uint8x8_t hex_lo = vqtbl1_u8(hex_table, lo);

        /* Interleave high and low hex characters */
        uint8x8x2_t zipped = vzip_u8(hex_hi, hex_lo);
        vst1_u8((uint8_t *)(dst + i * 2), zipped.val[0]);
        vst1_u8((uint8_t *)(dst + i * 2 + 8), zipped.val[1]);

        i += 8;
    }
#endif

    /* Scalar remainder */
    for (; i < src_len; i++) {
        uint8_t b = src[i];
        dst[i * 2]     = hex_chars[b >> 4];
        dst[i * 2 + 1] = hex_chars[b & 0x0F];
    }
}

size_t filament_format_hex_line(
    uint32_t offset,
    const uint8_t *data,
    size_t length,
    char *out_buf
) {
    size_t written = 0;
    size_t col;

    /* Write 8-hex-digit offset: "00000000  " */
    written += (size_t)snprintf(out_buf + written, 12, "%08x  ", offset);

    /* Write up to 16 hex bytes */
    for (col = 0; col < 16; col++) {
        if (col < length) {
            uint8_t b = data[col];
            out_buf[written++] = hex_chars[b >> 4];
            out_buf[written++] = hex_chars[b & 0x0F];
            out_buf[written++] = ' ';
        } else {
            out_buf[written++] = ' ';
            out_buf[written++] = ' ';
            out_buf[written++] = ' ';
        }

        if (col == 7) {
            out_buf[written++] = ' ';
        }
    }

    out_buf[written++] = ' ';
    out_buf[written++] = '|';

    /* ASCII characters */
    for (col = 0; col < length && col < 16; col++) {
        uint8_t b = data[col];
        if (b >= 32 && b <= 126) {
            out_buf[written++] = (char)b;
        } else {
            out_buf[written++] = '.';
        }
    }

    out_buf[written++] = '|';
    out_buf[written++] = '\n';
    out_buf[written] = '\0';

    return written;
}
