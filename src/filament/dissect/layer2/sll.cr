# =============================================================================
# sll.cr - Linux Cooked Capture (SLL and SLL2) dissector
# =============================================================================
#
# When capturing on the Linux "any" pseudo-interface or on non-Ethernet devices
# (such as loopback, PPP links, or WireGuard tunnels), the Linux kernel synthesizes
# a fake link-layer header called "Linux cooked capture" (SLL).
#
# Wire layout (SLL v1, 16 bytes):
#   - Packet type (16 bits): 0=host, 1=broadcast, 2=multicast, 3=other, 4=outgoing
#   - ARPHRD hardware type (16 bits): 1=Ethernet, 772=Loopback, 65534=Raw IP
#   - Address length (16 bits)
#   - Address bytes (8 bytes)
#   - Protocol (EtherType, 16 bits)
#
# Wire layout (SLL v2, 20 bytes):
#   - Protocol (16 bits)
#   - Reserved (16 bits)
#   - Interface index (32 bits)
#   - ARPHRD hardware type (16 bits)
#   - Packet type (8 bits)
#   - Address length (8 bits)
#   - Address bytes (8 bytes)
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"
require "./ethernet"

module Filament
  module Dissect
    module Layer2
      class SllDissector < Dissector
        def protocol : Protocol
          Protocol::Sll
        end

        def name : String
          "Linux Cooked Capture"
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 16_u32
            errors << "Truncated SLL frame: #{available} bytes available, minimum 16 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          # Default to SLL v1 parsing
          packet_type = (data[start].to_u16 << 8) | data[start + 1].to_u16
          arphrd = (data[start + 2].to_u16 << 8) | data[start + 3].to_u16
          addr_len = (data[start + 4].to_u16 << 8) | data[start + 5].to_u16
          ethertype = (data[start + 14].to_u16 << 8) | data[start + 15].to_u16

          fields["sll.packet_type"] = packet_type
          fields["sll.arphrd"] = arphrd
          fields["sll.addr_len"] = addr_len
          fields["sll.protocol"] = ethertype

          payload_offset = offset + 16_u32
          payload_len = data.size.to_u32 - payload_offset

          next_proto : Protocol? = case ethertype
                                   when EtherType::IPV4 then Protocol::IPv4
                                   when EtherType::IPV6 then Protocol::IPv6
                                   when EtherType::ARP  then Protocol::Arp
                                   else nil
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
