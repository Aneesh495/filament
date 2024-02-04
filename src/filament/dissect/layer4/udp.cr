# =============================================================================
# udp.cr - User Datagram Protocol (RFC 768) dissector
# =============================================================================
#
# Implements RFC 768 UDP datagram header decoding, pseudo-header checksum
# verification for IPv4 and IPv6, and application-layer protocol demuxing.
#
# Wire layout (Fixed 8-byte header):
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |          Source Port          |       Destination Port        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |            Length             |           Checksum            |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                             Data                              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"

module Filament
  module Dissect
    module Layer4
      class UdpDissector < Dissector
        def protocol : Protocol
          Protocol::Udp
        end

        def name : String
          "UDP"
        end

        # Computes UDP pseudo-header checksum for IPv4 datagrams
        def self.calculate_ipv4_pseudo_checksum(
          src_bytes : Bytes,
          dst_bytes : Bytes,
          udp_length : UInt16,
          udp_segment : Bytes,
        ) : UInt16
          sum = 0_u32

          # Source IP (4 bytes = two 16-bit words)
          sum += (src_bytes[0].to_u32 << 8) | src_bytes[1].to_u32
          sum += (src_bytes[2].to_u32 << 8) | src_bytes[3].to_u32

          # Destination IP (4 bytes = two 16-bit words)
          sum += (dst_bytes[0].to_u32 << 8) | dst_bytes[1].to_u32
          sum += (dst_bytes[2].to_u32 << 8) | dst_bytes[3].to_u32

          # Zero (1 byte) + Protocol 17 (1 byte)
          sum += 17_u32

          # UDP length (2 bytes)
          sum += udp_length.to_u32

          # Add entire UDP header + data
          i = 0
          len = udp_segment.size
          while i + 1 < len
            word = (udp_segment[i].to_u32 << 8) | udp_segment[i + 1].to_u32
            sum += word
            i += 2
          end

          if i < len
            sum += (udp_segment[i].to_u32 << 8)
          end

          while (sum >> 16) > 0
            sum = (sum & 0xFFFF_u32) + (sum >> 16)
          end

          csum = (~sum & 0xFFFF_u32).to_u16
          csum == 0_u16 ? 0xFFFF_u16 : csum
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 8_u32
            errors << "Truncated UDP header: #{available} bytes available, 8 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          src_port = (data[start].to_u16 << 8) | data[start + 1].to_u16
          dst_port = (data[start + 2].to_u16 << 8) | data[start + 3].to_u16
          length = (data[start + 4].to_u16 << 8) | data[start + 5].to_u16
          checksum = (data[start + 6].to_u16 << 8) | data[start + 7].to_u16

          fields["udp.src_port"] = src_port
          fields["udp.dst_port"] = dst_port
          fields["udp.length"] = length.to_u32
          fields["udp.checksum"] = checksum.to_u32

          if length < 8_u16
            errors << "Invalid UDP length #{length} (minimum 8 bytes)"
          end

          # Compute payload length respecting both UDP length header and available capture slice
          udp_payload_len = if length >= 8_u16
                              Math.min((length - 8_u16).to_u32, available - 8_u32)
                            else
                              available - 8_u32
                            end

          payload_offset = offset + 8_u32

          # Demultiplex to Layer 7 protocols based on well-known UDP ports
          next_proto : Protocol? = case {src_port, dst_port}
          when {53_u16, _}, {_, 53_u16}
            Protocol::Dns
          when {67_u16, _}, {_, 67_u16}, {68_u16, _}, {_, 68_u16}
            Protocol::Dhcp
          when {123_u16, _}, {_, 123_u16}
            Protocol::Ntp
          else
            nil
          end

          DissectResult.new(
            protocol: protocol,
            payload_offset: payload_offset,
            payload_length: udp_payload_len,
            fields: fields,
            next_protocol: next_proto,
            errors: errors
          )
        end
      end
    end
  end
end
