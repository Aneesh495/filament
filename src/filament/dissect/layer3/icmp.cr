# =============================================================================
# icmp.cr - Internet Control Message Protocol version 4 (RFC 792) dissector
# =============================================================================
#
# Implements RFC 792 ICMPv4 message decoding, checksum verification, and
# embedded error payload extraction for network troubleshooting and PMTU
# discovery.
#
# Wire layout (8-byte base header):
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |     Type      |     Code      |          Checksum             |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                 Type-Specific Data (4 bytes)                  |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |             Original IP Header + 64 bits of Payload           |
#  /                 (Only present in error messages)              /
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
      module IcmpType
        ECHO_REPLY           =  0_u8
        DEST_UNREACHABLE     =  3_u8
        SOURCE_QUENCH        =  4_u8
        REDIRECT             =  5_u8
        ECHO_REQUEST         =  8_u8
        ROUTER_ADVERTISEMENT =  9_u8
        ROUTER_SOLICITATION  = 10_u8
        TIME_EXCEEDED        = 11_u8
        PARAMETER_PROBLEM    = 12_u8
        TIMESTAMP_REQUEST    = 13_u8
        TIMESTAMP_REPLY      = 14_u8
      end

      class IcmpDissector < Dissector
        def protocol : Protocol
          Protocol::Icmp
        end

        def name : String
          "ICMP"
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 8_u32
            errors << "Truncated ICMP header: #{available} bytes available, 8 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          icmp_type = data[start]
          icmp_code = data[start + 1]
          checksum = (data[start + 2].to_u16 << 8) | data[start + 3].to_u16
          rest_of_header = (data[start + 4].to_u32 << 24) |
                           (data[start + 5].to_u32 << 16) |
                           (data[start + 6].to_u32 << 8) |
                           data[start + 7].to_u32

          fields["icmp.type"] = icmp_type.to_u32
          fields["icmp.code"] = icmp_code.to_u32
          fields["icmp.checksum"] = checksum.to_u32

          # Verify ICMP checksum over the entire ICMP message
          msg_slice = data[start, available.to_i32]
          calc_csum = IPv4Dissector.calculate_checksum(msg_slice)
          fields["icmp.checksum_valid"] = (calc_csum == 0_u16)

          type_name = case icmp_type
                      when IcmpType::ECHO_REPLY        then "Echo (ping) reply"
                      when IcmpType::DEST_UNREACHABLE  then "Destination unreachable"
                      when IcmpType::SOURCE_QUENCH     then "Source quench"
                      when IcmpType::REDIRECT          then "Redirect"
                      when IcmpType::ECHO_REQUEST      then "Echo (ping) request"
                      when IcmpType::TIME_EXCEEDED     then "Time exceeded"
                      when IcmpType::PARAMETER_PROBLEM then "Parameter problem"
                      when IcmpType::TIMESTAMP_REQUEST then "Timestamp request"
                      when IcmpType::TIMESTAMP_REPLY   then "Timestamp reply"
                      else                                  "Type #{icmp_type}"
                      end
          fields["icmp.type_name"] = type_name

          case icmp_type
          when IcmpType::ECHO_REQUEST, IcmpType::ECHO_REPLY
            ident = (data[start + 4].to_u16 << 8) | data[start + 5].to_u16
            seq = (data[start + 6].to_u16 << 8) | data[start + 7].to_u16
            fields["icmp.ident"] = ident.to_u32
            fields["icmp.seq"] = seq.to_u32
          when IcmpType::DEST_UNREACHABLE
            code_desc = case icmp_code
                        when 0 then "Net unreachable"
                        when 1 then "Host unreachable"
                        when 2 then "Protocol unreachable"
                        when 3 then "Port unreachable"
                        when 4
                          next_hop_mtu = (data[start + 6].to_u16 << 8) | data[start + 7].to_u16
                          fields["icmp.next_hop_mtu"] = next_hop_mtu.to_u32
                          "Fragmentation needed and DF set (MTU #{next_hop_mtu})"
                        when 5 then "Source route failed"
                        else        "Code #{icmp_code}"
                        end
            fields["icmp.code_desc"] = code_desc
            extract_embedded_ip(data, start + 8, fields)
          when IcmpType::TIME_EXCEEDED
            code_desc = (icmp_code == 0_u8) ? "TTL expired in transit" : "Fragment reassembly time exceeded"
            fields["icmp.code_desc"] = code_desc
            extract_embedded_ip(data, start + 8, fields)
          when IcmpType::REDIRECT
            gw_ip = Layer2::ArpDissector.format_ipv4(data[start + 4, 4])
            fields["icmp.gateway"] = gw_ip
            extract_embedded_ip(data, start + 8, fields)
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

        # Extracts original IP header from ICMP error payloads for fault correlation
        private def extract_embedded_ip(data : Bytes, offset : Int32, fields : Hash(String, FieldValue)) : Nil
          return if offset + 20 > data.size

          orig_proto = data[offset + 9]
          orig_src = Layer2::ArpDissector.format_ipv4(data[offset + 12, 4])
          orig_dst = Layer2::ArpDissector.format_ipv4(data[offset + 16, 4])

          fields["icmp.orig.proto"] = orig_proto.to_u32
          fields["icmp.orig.src"] = orig_src
          fields["icmp.orig.dst"] = orig_dst

          # If original transport header has at least 4 bytes (ports for TCP/UDP)
          orig_ihl = (data[offset] & 0x0F_u8).to_i32 * 4
          trans_offset = offset + orig_ihl
          if trans_offset + 4 <= data.size
            orig_sp = (data[trans_offset].to_u16 << 8) | data[trans_offset + 1].to_u16
            orig_dp = (data[trans_offset + 2].to_u16 << 8) | data[trans_offset + 3].to_u16
            fields["icmp.orig.src_port"] = orig_sp.to_u32
            fields["icmp.orig.dst_port"] = orig_dp.to_u32
          end
        end
      end
    end
  end
end
