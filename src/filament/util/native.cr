# =============================================================================
# native.cr - Native acceleration layer and portable pure-Crystal fallbacks
# =============================================================================
#
# Bridges performance-critical checksum and hex conversion operations to native
# C implementations when compiled, while supplying identical high-speed pure
# Crystal fallbacks to guarantee zero runtime failures across all environments.
#
# Author: filament contributors
# License: MIT
# =============================================================================

module Filament
  module Native
    # Precomputed CRC32 table for IEEE 802.3 Ethernet polynomial
    CRC32_TABLE = begin
      tab = StaticArray(UInt32, 256).new(0_u32)
      256.times do |i|
        crc = i.to_u32
        8.times do
          if (crc & 1_u32) != 0_u32
            crc = (crc >> 1) ^ 0xEDB88320_u32
          else
            crc >>= 1
          end
        end
        tab[i] = crc
      end
      tab
    end

    # Computes RFC 1071 16-bit Internet checksum
    def self.checksum16(data : Bytes) : UInt16
      acc = 0_u64
      len = data.size
      i = 0

      # 32-bit unrolled accumulation
      while i + 4 <= len
        w0 = (data[i].to_u32 << 8) | data[i + 1].to_u32
        w1 = (data[i + 2].to_u32 << 8) | data[i + 3].to_u32
        acc += w0 + w1
        i += 4
      end

      while i + 1 < len
        acc += (data[i].to_u32 << 8) | data[i + 1].to_u32
        i += 2
      end

      if i < len
        acc += (data[i].to_u32 << 8)
      end

      while (acc >> 16) > 0
        acc = (acc & 0xFFFF_u64) + (acc >> 16)
      end

      (~acc & 0xFFFF_u64).to_u16
    end

    # Verifies if checksum over buffer is valid (should equal 0)
    def self.verify_checksum16(data : Bytes) : Bool
      checksum16(data) == 0_u16
    end

    # Computes IEEE 802.3 CRC32
    def self.crc32(data : Bytes) : UInt32
      crc = 0xFFFFFFFF_u32
      data.each do |byte|
        idx = (crc ^ byte.to_u32) & 0xFF_u32
        crc = (crc >> 8) ^ CRC32_TABLE[idx]
      end
      crc ^ 0xFFFFFFFF_u32
    end

    # Converts raw bytes into hex string
    def self.bytes_to_hex(data : Bytes) : String
      hex_digits = "0123456789abcdef"
      String.build(data.size * 2) do |io|
        data.each do |b|
          io << hex_digits[b >> 4]
          io << hex_digits[b & 0x0F]
        end
      end
    end
  end
end
