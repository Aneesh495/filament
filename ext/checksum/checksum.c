/*
 * checksum.c - Optimized Internet checksum and CRC32 implementation
 *
 * Implements 64-bit unrolled accumulation loops for RFC 1071 checksums.
 * By accumulating into a 64-bit unsigned integer, we can process up to
 * 2^48 bytes before any possible integer overflow occurs, completely
 * eliminating inner-loop carry-propagation branches.
 *
 * Author: filament contributors
 * License: MIT
 */

#include "checksum.h"

uint16_t filament_checksum16(const uint8_t *data, size_t length) {
    uint64_t acc = 0;
    const uint64_t *ptr64;
    const uint16_t *ptr16;

    /* Align to 64-bit boundary if needed */
    while (((uintptr_t)data & 7) != 0 && length >= 2) {
        acc += ((uint16_t)data[0] << 8) | data[1];
        data += 2;
        length -= 2;
    }

    /* 64-bit unrolled main loop: 32 bytes per iteration */
    ptr64 = (const uint64_t *)data;
    while (length >= 32) {
        uint64_t w0 = ptr64[0];
        uint64_t w1 = ptr64[1];
        uint64_t w2 = ptr64[2];
        uint64_t w3 = ptr64[3];

        /* Swap bytes if on little-endian machine */
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        w0 = __builtin_bswap64(w0);
        w1 = __builtin_bswap64(w1);
        w2 = __builtin_bswap64(w2);
        w3 = __builtin_bswap64(w3);
        #endif

        acc += (w0 >> 48) + ((w0 >> 32) & 0xFFFF) + ((w0 >> 16) & 0xFFFF) + (w0 & 0xFFFF);
        acc += (w1 >> 48) + ((w1 >> 32) & 0xFFFF) + ((w1 >> 16) & 0xFFFF) + (w1 & 0xFFFF);
        acc += (w2 >> 48) + ((w2 >> 32) & 0xFFFF) + ((w2 >> 16) & 0xFFFF) + (w2 & 0xFFFF);
        acc += (w3 >> 48) + ((w3 >> 32) & 0xFFFF) + ((w3 >> 16) & 0xFFFF) + (w3 & 0xFFFF);

        ptr64 += 4;
        length -= 32;
    }

    /* Process remaining 16-bit words */
    data = (const uint8_t *)ptr64;
    ptr16 = (const uint16_t *)data;
    while (length >= 2) {
        uint16_t val = *ptr16++;
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        val = __builtin_bswap16(val);
        #endif
        acc += val;
        length -= 2;
    }

    /* Trailing odd byte */
    data = (const uint8_t *)ptr16;
    if (length == 1) {
        acc += ((uint16_t)data[0]) << 8;
    }

    /* Fold 64-bit accumulator into 16 bits */
    while (acc >> 16) {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }

    return (uint16_t)(~acc & 0xFFFF);
}

int filament_verify_checksum16(const uint8_t *data, size_t length) {
    uint16_t csum = filament_checksum16(data, length);
    return (csum == 0);
}

uint16_t filament_ipv4_pseudo_checksum(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t protocol,
    uint16_t length,
    const uint8_t *payload,
    size_t payload_len
) {
    uint64_t acc = 0;

    /* Pseudo-header fields */
    acc += (src_ip >> 16) + (src_ip & 0xFFFF);
    acc += (dst_ip >> 16) + (dst_ip & 0xFFFF);
    acc += (uint16_t)protocol;
    acc += length;

    /* Add payload */
    while (payload_len >= 2) {
        uint16_t val = ((uint16_t)payload[0] << 8) | payload[1];
        acc += val;
        payload += 2;
        payload_len -= 2;
    }

    if (payload_len == 1) {
        acc += ((uint16_t)payload[0]) << 8;
    }

    while (acc >> 16) {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }

    uint16_t result = (uint16_t)(~acc & 0xFFFF);
    return (result == 0) ? 0xFFFF : result;
}

/* Precomputed CRC32 table for IEEE 802.3 Ethernet polynomial (0xEDB88320) */
static const uint32_t crc32_tab[16] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};

uint32_t filament_crc32(const uint8_t *data, size_t length) {
    uint32_t crc = ~0U;
    size_t i;

    for (i = 0; i < length; i++) {
        crc ^= data[i];
        crc = (crc >> 4) ^ crc32_tab[crc & 0x0F];
        crc = (crc >> 4) ^ crc32_tab[crc & 0x0F];
    }

    return ~crc;
}
