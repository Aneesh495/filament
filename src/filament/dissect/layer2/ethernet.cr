# =============================================================================
# ethernet.cr - Ethernet II and IEEE 802.1Q VLAN frame dissector
# =============================================================================
#
# Implements decoding for DIX Ethernet II frames, standard IEEE 802.1Q VLAN
# tagged encapsulation, and IEEE 802.1ad QinQ double-tagging.
#
# Wire layout (Ethernet II):
#   +---------------------------------------------+
#   | Destination MAC Address (6 bytes)           |
#   +---------------------------------------------+
#   | Source MAC Address (6 bytes)                |
#   +---------------------------------------------+
#   | EtherType (2 bytes)                         |
#   +---------------------------------------------+
#   | Payload (46 to 1500 bytes)                  |
#   +---------------------------------------------+
#
# If EtherType is 0x8100 (802.1Q) or 0x88A8 (QinQ), a 4-byte tag follows:
#   - 3 bits: Priority Code Point (PCP)
#   - 1 bit:  Drop Eligible Indicator (DEI)
#   - 12 bits: VLAN Identifier (VID, 0 to 4095)
#   - 16 bits: Inner EtherType
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"

module Filament
  module Dissect
    module Layer2
      # Standard EtherType constants
      module EtherType
        IPV4          = 0x0800_u16
        ARP           = 0x0806_u16
        VLAN_8021Q    = 0x8100_u16
        IPV6          = 0x86DD_u16
        MPLS_UNICAST  = 0x8847_u16
        PPPOE_SESSION = 0x8864_u16
        VLAN_QINQ     = 0x88A8_u16
        LLDP          = 0x88CC_u16
      end

      # Dissects Ethernet II and VLAN frames
      class EthernetDissector < Dissector
        def protocol : Protocol
          Protocol::Ethernet
        end

        def name : String
          "Ethernet II"
        end

        # Formats a 6-byte slice into colon-separated hex MAC notation
        def self.format_mac(bytes : Bytes) : String
          return "00:00:00:00:00:00" if bytes.size < 6
          sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
        end

        # Parses MAC address string back to 6 bytes
        def self.parse_mac(str : String) : Bytes?
          clean = str.gsub(/[:-]/, "")
          return nil unless clean.size == 12
          bytes = Bytes.new(6)
          6.times do |i|
            hex = clean[i * 2, 2]
            val = hex.to_u8?(16)
            return nil unless val
            bytes[i] = val
          end
          bytes
        end

        # Dissects raw frame data starting at given offset
        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 14_u32
            errors << "Truncated Ethernet frame: #{available} bytes available, minimum 14 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start_idx = offset.to_i32
          dst_bytes = data[start_idx, 6]
          src_bytes = data[start_idx + 6, 6]

          dst_mac = EthernetDissector.format_mac(dst_bytes)
          src_mac = EthernetDissector.format_mac(src_bytes)

          # Extract MAC address properties
          dst_multicast = (dst_bytes[0] & 0x01_u8) != 0_u8
          dst_broadcast = (dst_bytes == Bytes[0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
          src_local = (src_bytes[0] & 0x02_u8) != 0_u8

          fields["eth.dst"] = dst_mac
          fields["eth.src"] = src_mac
          fields["eth.dst.multicast"] = dst_multicast
          fields["eth.dst.broadcast"] = dst_broadcast
          fields["eth.src.local"] = src_local

          # Read EtherType (big-endian 16-bit word)
          ethertype = (data[start_idx + 12].to_u16 << 8) | data[start_idx + 13].to_u16
          fields["eth.type"] = ethertype

          hdr_len = 14_u32
          current_offset = offset + 14_u32

          # Handle 802.1Q Single VLAN tag
          if ethertype == EtherType::VLAN_8021Q && available >= 18_u32
            tci = (data[start_idx + 14].to_u16 << 8) | data[start_idx + 15].to_u16
            pcp = ((tci >> 13) & 0x07_u16).to_u8
            dei = ((tci >> 12) & 0x01_u16) != 0_u16
            vid = tci & 0x0FFF_u16
            inner_ethertype = (data[start_idx + 16].to_u16 << 8) | data[start_idx + 17].to_u16

            fields["vlan.id"] = vid.to_u32
            fields["vlan.pcp"] = pcp
            fields["vlan.dei"] = dei
            fields["vlan.inner_type"] = inner_ethertype

            ethertype = inner_ethertype
            hdr_len = 18_u32
            current_offset = offset + 18_u32
            # Handle 802.1ad QinQ Double VLAN tags
          elsif ethertype == EtherType::VLAN_QINQ && available >= 22_u32
            outer_tci = (data[start_idx + 14].to_u16 << 8) | data[start_idx + 15].to_u16
            outer_vid = outer_tci & 0x0FFF_u16
            inner_tag_proto = (data[start_idx + 16].to_u16 << 8) | data[start_idx + 17].to_u16

            if inner_tag_proto == EtherType::VLAN_8021Q
              inner_tci = (data[start_idx + 18].to_u16 << 8) | data[start_idx + 19].to_u16
              inner_vid = inner_tci & 0x0FFF_u16
              inner_ethertype = (data[start_idx + 20].to_u16 << 8) | data[start_idx + 21].to_u16

              fields["qinq.outer_vid"] = outer_vid.to_u32
              fields["qinq.inner_vid"] = inner_vid.to_u32
              fields["qinq.inner_type"] = inner_ethertype

              ethertype = inner_ethertype
              hdr_len = 22_u32
              current_offset = offset + 22_u32
            end
          end

          payload_len = data.size.to_u32 - current_offset

          # Demultiplex to Layer 3
          next_proto : Protocol? = case ethertype
          when EtherType::IPV4
            Protocol::IPv4
          when EtherType::IPV6
            Protocol::IPv6
          when EtherType::ARP
            Protocol::Arp
          else
            nil
          end

          DissectResult.new(
            protocol: protocol,
            payload_offset: current_offset,
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
