/*
 * checksum.h - High-performance packet checksum acceleration primitives
 *
 * Implements RFC 1071 16-bit one's complement Internet checksum calculation
 * using 64-bit accumulator unrolling, as well as IEEE 802.3 Ethernet CRC32.
 *
 * Author: filament contributors
 * License: MIT
 */

#ifndef FILAMENT_CHECKSUM_H
#define FILAMENT_CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Calculates the RFC 1071 Internet checksum over a memory buffer.
 * Returns the 16-bit one's complement sum.
 */
uint16_t filament_checksum16(const uint8_t *data, size_t length);

/*
 * Validates whether an RFC 1071 checksum is correct.
 * When computed over a header including the checksum field,
 * the result should be 0 (or 0xFFFF prior to final complement).
 */
int filament_verify_checksum16(const uint8_t *data, size_t length);

/*
 * Calculates the IPv4 pseudo-header checksum for transport protocols.
 */
uint16_t filament_ipv4_pseudo_checksum(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t protocol,
    uint16_t length,
    const uint8_t *payload,
    size_t payload_len
);

/*
 * Computes standard IEEE 802.3 32-bit CRC (Ethernet Frame Check Sequence).
 */
uint32_t filament_crc32(const uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* FILAMENT_CHECKSUM_H */
