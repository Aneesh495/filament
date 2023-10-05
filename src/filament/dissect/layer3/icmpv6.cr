# =============================================================================
# icmpv6.cr - Internet Control Message Protocol for IPv6 (RFC 4443 / RFC 4861)
# =============================================================================
#
# Implements decoding for ICMPv6 messages including Ping, Path MTU Discovery,
# and the complete Neighbor Discovery Protocol (NDP) suite that replaces ARP
# in IPv6 networks.
#
# Wire layout (8-byte base header):
#   - Type (8 bits)
#   - Code (8 bits)
#   - Checksum (16 bits)
#   - Message body (variable length depending on message type)
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"
require "./ipv6"
require "../layer2/ethernet"

module Filament
  module Dissect
    module Layer3
      module Icmpv6Type
        DEST_UNREACHABLE     = 1_u8
        PACKET_TOO_BIG       = 2_u8
        TIME_EXCEEDED        = 3_u8
        PARAMETER_PROBLEM    = 4_u8
        ECHO_REQUEST         = 128_u8
        ECHO_REPLY           = 129_u8
        ROUTER_SOLICITATION  = 133_u8
        ROUTER_ADVERT        = 134_u8
        NEIGHBOR_SOLICIT     = 135_u8
        NEIGHBOR_ADVERT      = 136_u8
        REDIRECT             = 137_u8
      end

      class Icmpv6Dissector < Dissector
        def protocol : Protocol
          Protocol::Icmpv6
        end

        def name : String
          "ICMPv6"
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 8_u32
            errors << "Truncated ICMPv6 header: #{available} bytes available, 8 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          msg_type = data[start]
          code = data[start + 1]
          checksum = (data[start + 2].to_u16 << 8) | data[start + 3].to_u16

          fields["icmpv6.type"] = msg_type.to_u32
          fields["icmpv6.code"] = code.to_u32
          fields["icmpv6.checksum"] = checksum.to_u32

          type_name = case msg_type
                      when Icmpv6Type::DEST_UNREACHABLE    then "Destination Unreachable"
                      when Icmpv6Type::PACKET_TOO_BIG      then "Packet Too Big"
                      when Icmpv6Type::TIME_EXCEEDED       then "Time Exceeded"
                      when Icmpv6Type::PARAMETER_PROBLEM   then "Parameter Problem"
                      when Icmpv6Type::ECHO_REQUEST        then "Echo Request"
                      when Icmpv6Type::ECHO_REPLY          then "Echo Reply"
                      when Icmpv6Type::ROUTER_SOLICITATION then "Router Solicitation"
                      when Icmpv6Type::ROUTER_ADVERT       then "Router Advertisement"
                      when Icmpv6Type::NEIGHBOR_SOLICIT    then "Neighbor Solicitation"
                      when Icmpv6Type::NEIGHBOR_ADVERT     then "Neighbor Advertisement"
                      when Icmpv6Type::REDIRECT            then "Redirect"
                      else "Type #{msg_type}"
                      end
          fields["icmpv6.type_name"] = type_name

          case msg_type
          when Icmpv6Type::ECHO_REQUEST, Icmpv6Type::ECHO_REPLY
            ident = (data[start + 4].to_u16 << 8) | data[start + 5].to_u16
            seq = (data[start + 6].to_u16 << 8) | data[start + 7].to_u16
            fields["icmpv6.ident"] = ident.to_u32
            fields["icmpv6.seq"] = seq.to_u32

          when Icmpv6Type::PACKET_TOO_BIG
            mtu = (data[start + 4].to_u32 << 24) |
                  (data[start + 5].to_u32 << 16) |
                  (data[start + 6].to_u32 << 8) |
                  data[start + 7].to_u32
            fields["icmpv6.mtu"] = mtu

          when Icmpv6Type::NEIGHBOR_SOLICIT
            if available >= 24_u32
              target_ip = IPv6Dissector.format_ipv6(data[start + 8, 16])
              fields["icmpv6.target_ip"] = target_ip
              parse_ndp_options(data, start + 24, available.to_i32 - 24, fields)
            end

          when Icmpv6Type::NEIGHBOR_ADVERT
            if available >= 24_u32
              flags_byte = data[start + 4]
              router_flag = (flags_byte & 0x80_u8) != 0_u8
              solicited_flag = (flags_byte & 0x40_u8) != 0_u8
              override_flag = (flags_byte & 0x20_u8) != 0_u8

              fields["icmpv6.ndp.router"] = router_flag
              fields["icmpv6.ndp.solicited"] = solicited_flag
              fields["icmpv6.ndp.override"] = override_flag

              target_ip = IPv6Dissector.format_ipv6(data[start + 8, 16])
              fields["icmpv6.target_ip"] = target_ip
              parse_ndp_options(data, start + 24, available.to_i32 - 24, fields)
            end
          end

          payload_offset = offset + 8_u32
          payload_len = available - 8_u32

          DissectResult.new(
            protocol: protocol,
            payload_offset: payload_offset,
            payload_length: payload_len,
            fields: fields,
            next_protocol: nil,
            errors: errors
          )
        end

        # Decodes NDP TLV options (Source/Target Link-Layer Address, MTU, Prefix Info)
        private def parse_ndp_options(data : Bytes, offset : Int32, len : Int32, fields : Hash(String, FieldValue)) : Nil
          idx = offset
          end_idx = offset + len

          while idx + 2 <= end_idx
            opt_type = data[idx]
            opt_len_units = data[idx + 1].to_i32
            break if opt_len_units == 0
            opt_bytes_len = opt_len_units * 8
            break if idx + opt_bytes_len > end_idx

            case opt_type
            when 1_u8 # Source Link-Layer Address
              if opt_bytes_len >= 8
                mac = Layer2::EthernetDissector.format_mac(data[idx + 2, 6])
                fields["icmpv6.ndp.source_mac"] = mac
              end
            when 2_u8 # Target Link-Layer Address
              if opt_bytes_len >= 8
                mac = Layer2::EthernetDissector.format_mac(data[idx + 2, 6])
                fields["icmpv6.ndp.target_mac"] = mac
              end
            when 5_u8 # MTU
              if opt_bytes_len >= 8
                mtu = (data[idx + 4].to_u32 << 24) |
                      (data[idx + 5].to_u32 << 16) |
                      (data[idx + 6].to_u32 << 8) |
                      data[idx + 7].to_u32
                fields["icmpv6.ndp.opt_mtu"] = mtu
              end
            end

            idx += opt_bytes_len
          end
        end
      end
    end
  end
end
