# =============================================================================
# ppp.cr - Point-to-Point Protocol (RFC 1661) dissector
# =============================================================================
#
# Implements decoding for PPP frames used on serial lines, cellular modems,
# and PPPoE DSL/FTTH connections.
#
# Wire layout (HDLC-like framing):
#   - Address (8 bits, typically 0xFF)
#   - Control (8 bits, typically 0x03)
#   - Protocol (8 or 16 bits: 0x0021=IPv4, 0x0057=IPv6, 0x8021=IPCP, 0xC021=LCP)
#   - Information payload
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"

module Filament
  module Dissect
    module Layer2
      module PppProtocol
        IPV4   = 0x0021_u16
        IPV6   = 0x0057_u16
        IPCP   = 0x8021_u16
        IPV6CP = 0x8057_u16
        LCP    = 0xC021_u16
        PAP    = 0xC023_u16
        CHAP   = 0xC223_u16
      end

      class PppDissector < Dissector
        def protocol : Protocol
          Protocol::Ppp
        end

        def name : String
          "PPP"
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 2_u32
            errors << "Truncated PPP frame: #{available} bytes available"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32
          proto_id = 0_u16
          hdr_len = 0_u32

          # Check if Address (0xFF) and Control (0x03) fields are present
          if available >= 4_u32 && data[start] == 0xFF_u8 && data[start + 1] == 0x03_u8
            fields["ppp.address"] = data[start]
            fields["ppp.control"] = data[start + 1]
            proto_id = (data[start + 2].to_u16 << 8) | data[start + 3].to_u16
            hdr_len = 4_u32
          else
            # Compressed header without Address and Control
            if (data[start] & 0x01_u8) != 0_u8
              # 8-bit compressed protocol ID
              proto_id = data[start].to_u16
              hdr_len = 1_u32
            else
              proto_id = (data[start].to_u16 << 8) | data[start + 1].to_u16
              hdr_len = 2_u32
            end
          end

          fields["ppp.protocol"] = proto_id
          payload_offset = offset + hdr_len
          payload_len = data.size.to_u32 - payload_offset

          next_proto : Protocol? = case proto_id
          when PppProtocol::IPV4 then Protocol::IPv4
          when PppProtocol::IPV6 then Protocol::IPv6
          else                        nil
          end

          DissectResult.new(
            protocol: protocol,
            payload_offset: payload_offset,
            payload_length: payload_len,
            fields: fields,
            next_protocol: next_proto,
            errors: errors
          )
        end
      end
    end
  end
end
