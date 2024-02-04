# =============================================================================
# ipv6.cr - Internet Protocol version 6 (RFC 8200) dissector
# =============================================================================
#
# Implements RFC 8200 IPv6 fixed header decoding, canonical RFC 5952 text
# address formatting with zero-compression, and extension header chaining.
#
# Wire layout (Fixed 40-byte header):
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |Version| Traffic Class |           Flow Label                  |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |         Payload Length        |  Next Header  |   Hop Limit   |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  +                                                               +
#  |                                                               |
#  +                         Source Address                        +
#  |                           (128 bits)                          |
#  +                                                               +
#  |                                                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                                                               |
#  +                                                               +
#  |                                                               |
#  +                      Destination Address                      +
#  |                           (128 bits)                          |
#  +                                                               +
#  |                                                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"
require "./ipv4"

module Filament
  module Dissect
    module Layer3
      # IPv6 Extension Header types
      module IPv6ExtensionHeader
        HOP_BY_HOP =   0_u8
        ROUTING    =  43_u8
        FRAGMENT   =  44_u8
        ESP        =  50_u8
        AH         =  51_u8
        DEST_OPTS  =  60_u8
        MOBILITY   = 135_u8
        NO_NEXT    =  59_u8
      end

      class IPv6Dissector < Dissector
        def protocol : Protocol
          Protocol::IPv6
        end

        def name : String
          "IPv6"
        end

        # Formats a 16-byte slice into RFC 5952 canonical IPv6 string with :: compression
        def self.format_ipv6(bytes : Bytes) : String
          return "::" if bytes.size < 16

          # Unpack eight 16-bit words (big endian)
          words = StaticArray(UInt16, 8).new(0_u16)
          8.times do |i|
            words[i] = (bytes[i * 2].to_u16 << 8) | bytes[i * 2 + 1].to_u16
          end

          # Find longest run of consecutive zeros for :: compression
          best_start = -1
          best_len = 0
          cur_start = -1
          cur_len = 0

          8.times do |i|
            if words[i] == 0_u16
              if cur_start == -1
                cur_start = i
                cur_len = 1
              else
                cur_len += 1
              end
            else
              if cur_len > best_len && cur_len > 1
                best_start = cur_start
                best_len = cur_len
              end
              cur_start = -1
              cur_len = 0
            end
          end

          if cur_len > best_len && cur_len > 1
            best_start = cur_start
            best_len = cur_len
          end

          String.build do |io|
            i = 0
            while i < 8
              if i == best_start
                io << "::"
                i += best_len
                next
              end

              io << words[i].to_s(16)
              io << ":" if i < 7 && (i + 1) != best_start
              i += 1
            end
          end
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 40_u32
            errors << "Truncated IPv6 header: #{available} bytes available, 40 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          # First 32-bit word: Version (4), Traffic Class (8), Flow Label (20)
          word0 = (data[start].to_u32 << 24) |
                  (data[start + 1].to_u32 << 16) |
                  (data[start + 2].to_u32 << 8) |
                  data[start + 3].to_u32

          version = (word0 >> 28).to_u8
          traffic_class = ((word0 >> 20) & 0xFF_u32).to_u8
          flow_label = word0 & 0x000FFFFF_u32

          if version != 6_u8
            errors << "Invalid IPv6 version #{version}"
          end

          payload_len = (data[start + 4].to_u16 << 8) | data[start + 5].to_u16
          next_header = data[start + 6]
          hop_limit = data[start + 7]

          src_ip = IPv6Dissector.format_ipv6(data[start + 8, 16])
          dst_ip = IPv6Dissector.format_ipv6(data[start + 24, 16])

          fields["ipv6.version"] = version.to_u32
          fields["ipv6.traffic_class"] = traffic_class.to_u32
          fields["ipv6.flow_label"] = flow_label
          fields["ipv6.payload_len"] = payload_len.to_u32
          fields["ipv6.next_header"] = next_header.to_u32
          fields["ipv6.hop_limit"] = hop_limit.to_u32
          fields["ipv6.src"] = src_ip
          fields["ipv6.dst"] = dst_ip

          # Traverse extension header chain
          current_offset = offset + 40_u32
          current_next_hdr = next_header
          ext_hdrs = [] of String

          loop do
            case current_next_hdr
            when IPv6ExtensionHeader::HOP_BY_HOP, IPv6ExtensionHeader::ROUTING, IPv6ExtensionHeader::DEST_OPTS
              ext_start = current_offset.to_i32
              break if ext_start + 2 > data.size

              hdr_type_name = case current_next_hdr
                              when IPv6ExtensionHeader::HOP_BY_HOP then "Hop-by-Hop"
                              when IPv6ExtensionHeader::ROUTING    then "Routing"
                              else                                      "Destination Options"
                              end
              ext_hdrs << hdr_type_name

              current_next_hdr = data[ext_start]
              hdr_ext_len = data[ext_start + 1].to_u32
              total_ext_len = (hdr_ext_len + 1_u32) * 8_u32

              current_offset += total_ext_len
              break if current_offset > data.size.to_u32
            when IPv6ExtensionHeader::FRAGMENT
              ext_start = current_offset.to_i32
              break if ext_start + 8 > data.size

              ext_hdrs << "Fragment"
              current_next_hdr = data[ext_start]
              frag_offset_m = (data[ext_start + 2].to_u16 << 8) | data[ext_start + 3].to_u16
              frag_id = (data[ext_start + 4].to_u32 << 24) |
                        (data[ext_start + 5].to_u32 << 16) |
                        (data[ext_start + 6].to_u32 << 8) |
                        data[ext_start + 7].to_u32

              fields["ipv6.frag.offset"] = (frag_offset_m >> 3).to_u32 * 8_u32
              fields["ipv6.frag.m"] = (frag_offset_m & 0x01_u16) != 0_u16
              fields["ipv6.frag.id"] = frag_id

              current_offset += 8_u32
              break # Stop deeper parsing on fragment
            else
              break
            end
          end

          fields["ipv6.extensions"] = ext_hdrs.join(", ") unless ext_hdrs.empty?

          wire_payload_len = data.size.to_u32 - current_offset

          next_proto : Protocol? = case current_next_hdr
          when IpProtocol::TCP    then Protocol::Tcp
          when IpProtocol::UDP    then Protocol::Udp
          when IpProtocol::ICMPV6 then Protocol::Icmpv6
          else                         nil
          end

          DissectResult.new(
            protocol: protocol,
            payload_offset: current_offset,
            payload_length: wire_payload_len,
            fields: fields,
            next_protocol: next_proto,
            errors: errors
          )
        end
      end
    end
  end
end
