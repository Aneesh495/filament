# =============================================================================
# arp.cr - Address Resolution Protocol (RFC 826) dissector
# =============================================================================
#
# Implements decoding for ARP and RARP frames, mapping network-layer addresses
# (typically IPv4) to link-layer addresses (typically Ethernet MACs).
#
# Wire layout (Ethernet + IPv4, 28 bytes):
#   +---------------------------------------------+
#   | Hardware Type (HTYPE, 2 bytes)              |
#   +---------------------------------------------+
#   | Protocol Type (PTYPE, 2 bytes)              |
#   +----------------------+----------------------+
#   | Hardware Len (1 byte)| Protocol Len (1 byte)|
#   +----------------------+----------------------+
#   | Opcode (2 bytes: 1=Req, 2=Reply, 3=RARP)    |
#   +---------------------------------------------+
#   | Sender Hardware Address (SHA, 6 bytes)      |
#   +---------------------------------------------+
#   | Sender Protocol Address (SPA, 4 bytes)      |
#   +---------------------------------------------+
#   | Target Hardware Address (THA, 6 bytes)      |
#   +---------------------------------------------+
#   | Target Protocol Address (TPA, 4 bytes)      |
#   +---------------------------------------------+
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"
require "./ethernet"

module Filament
  module Dissect
    module Layer2
      module ArpOpcode
        REQUEST      = 1_u16
        REPLY        = 2_u16
        RARP_REQUEST = 3_u16
        RARP_REPLY   = 4_u16
      end

      # Dissects ARP / RARP packet headers
      class ArpDissector < Dissector
        def protocol : Protocol
          Protocol::Arp
        end

        def name : String
          "ARP"
        end

        # Formats a 4-byte slice into standard dotted-decimal notation
        def self.format_ipv4(bytes : Bytes) : String
          return "0.0.0.0" if bytes.size < 4
          "#{bytes[0]}.#{bytes[1]}.#{bytes[2]}.#{bytes[3]}"
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 28_u32
            errors << "Truncated ARP packet: #{available} bytes available, minimum 28 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          htype = (data[start].to_u16 << 8) | data[start + 1].to_u16
          ptype = (data[start + 2].to_u16 << 8) | data[start + 3].to_u16
          hlen = data[start + 4]
          plen = data[start + 5]
          opcode = (data[start + 6].to_u16 << 8) | data[start + 7].to_u16

          fields["arp.htype"] = htype
          fields["arp.ptype"] = ptype
          fields["arp.hlen"] = hlen
          fields["arp.plen"] = plen
          fields["arp.opcode"] = opcode

          op_name = case opcode
                    when ArpOpcode::REQUEST      then "Request"
                    when ArpOpcode::REPLY        then "Reply"
                    when ArpOpcode::RARP_REQUEST then "RARP Request"
                    when ArpOpcode::RARP_REPLY   then "RARP Reply"
                    else "Opcode #{opcode}"
                    end
          fields["arp.operation_name"] = op_name

          # We primarily decode Ethernet (hlen=6) and IPv4 (plen=4)
          if hlen == 6_u8 && plen == 4_u8 && available >= 28_u32
            sha = EthernetDissector.format_mac(data[start + 8, 6])
            spa = ArpDissector.format_ipv4(data[start + 14, 4])
            tha = EthernetDissector.format_mac(data[start + 18, 6])
            tpa = ArpDissector.format_ipv4(data[start + 24, 4])

            fields["arp.src_mac"] = sha
            fields["arp.src_ip"] = spa
            fields["arp.dst_mac"] = tha
            fields["arp.dst_ip"] = tpa

            # Detect Gratuitous ARP (announcement of one's own IP)
            is_gratuitous = (spa == tpa)
            fields["arp.is_gratuitous"] = is_gratuitous

            # Detect ARP Probe (RFC 5227 conflict detection: SPA is 0.0.0.0)
            is_probe = (spa == "0.0.0.0")
            fields["arp.is_probe"] = is_probe
          end

          DissectResult.new(
            protocol: protocol,
            payload_offset: offset + 28_u32,
            payload_length: 0_u32, # ARP terminates the stack
            fields: fields,
            next_protocol: nil,
            errors: errors
          )
        end
      end
    end
  end
end
