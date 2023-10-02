# =============================================================================
# ipv6_extensions.cr - IPv6 Extension Header decoders
# =============================================================================
#
# Provides specialized parsers for IPv6 Extension Headers as defined in
# RFC 8200, RFC 2675 (Jumbograms), and RFC 8754 (Segment Routing over IPv6).
#
# Unlike IPv4 options which reside in the fixed header (limited to 40 bytes),
# IPv6 options are carried in discrete extension headers inserted between
# the base IPv6 header and the transport layer. This allows arbitrary sizing
# and optimized forwarding paths.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./ipv6"

module Filament
  module Dissect
    module Layer3
      # Known option types within Hop-by-Hop and Destination Options
      module IPv6OptionType
        PAD1         = 0x00_u8
        PADN         = 0x01_u8
        JUMBO        = 0xC2_u8 # Jumbo payload option (RFC 2675)
        ROUTER_ALERT = 0x05_u8 # Router Alert (RFC 2711)
        CALIPSO      = 0x07_u8
        SMF_DPD      = 0x08_u8
        HOME_ADDRESS = 0xC9_u8 # Mobile IPv6
      end

      # Detailed decoder for IPv6 Hop-by-Hop and Destination Options
      class IPv6OptionsDecoder
        getter options : Hash(String, FieldValue)

        def initialize
          @options = Hash(String, FieldValue).new
        end

        # Parses TLV (Type-Length-Value) options within an extension header slice
        def decode_tlv(slice : Bytes) : Nil
          idx = 2 # Skip Next Header and Header Ext Len
          len = slice.size

          while idx < len
            opt_type = slice[idx]
            if opt_type == IPv6OptionType::PAD1
              idx += 1
              next
            end

            break if idx + 1 >= len
            opt_data_len = slice[idx + 1].to_i32
            break if idx + 2 + opt_data_len > len

            opt_data = slice[idx + 2, opt_data_len]

            case opt_type
            when IPv6OptionType::PADN
              # Padding bytes, ignore
            when IPv6OptionType::JUMBO
              if opt_data.size >= 4
                jumbo_len = (opt_data[0].to_u32 << 24) |
                            (opt_data[1].to_u32 << 16) |
                            (opt_data[2].to_u32 << 8) |
                            opt_data[3].to_u32
                @options["ipv6.opt.jumbo_length"] = jumbo_len
              end
            when IPv6OptionType::ROUTER_ALERT
              if opt_data.size >= 2
                val = (opt_data[0].to_u16 << 8) | opt_data[1].to_u16
                @options["ipv6.opt.router_alert"] = val.to_u32
              end
            end

            idx += 2 + opt_data_len
          end
        end
      end

      # Specialized decoder for Segment Routing Header (SRv6, RFC 8754)
      class SRv6Decoder
        getter segments_left : UInt8
        getter last_entry : UInt8
        getter flags : UInt8
        getter segments : Array(String)

        def initialize(@segments_left : UInt8, @last_entry : UInt8, @flags : UInt8, @segments : Array(String))
        end

        def self.decode(slice : Bytes) : SRv6Decoder?
          return nil if slice.size < 8
          # Routing Type must be 4 for SRv6
          routing_type = slice[2]
          return nil unless routing_type == 4_u8

          segs_left = slice[3]
          last_entry = slice[4]
          flags = slice[5]

          segments = [] of String
          seg_count = last_entry.to_i32 + 1
          expected_len = 8 + (seg_count * 16)
          return nil if slice.size < expected_len

          seg_count.times do |i|
            seg_start = 8 + (i * 16)
            seg_bytes = slice[seg_start, 16]
            segments << IPv6Dissector.format_ipv6(seg_bytes)
          end

          new(segs_left, last_entry, flags, segments)
        end
      end
    end
  end
end
