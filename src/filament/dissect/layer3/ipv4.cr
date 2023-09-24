# =============================================================================
# ipv4.cr - Internet Protocol version 4 (RFC 791) dissector
# =============================================================================
#
# Implements full RFC 791 IPv4 datagram header decoding, header checksum
# verification via one's complement addition, and optional variable-length
# option list parsing.
#
# Wire layout (20 to 60 bytes):
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |Version|  IHL  |Type of Service|          Total Length         |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |         Identification        |Flags|      Fragment Offset    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |  Time to Live |    Protocol   |        Header Checksum        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                       Source Address                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Destination Address                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Options                    |    Padding    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"
require "../layer2/arp"

module Filament
  module Dissect
    module Layer3
      # Standard IP protocol numbers (IANA)
      module IpProtocol
        ICMP   = 1_u8
        IGMP   = 2_u8
        TCP    = 6_u8
        UDP    = 17_u8
        IPV6   = 41_u8
        GRE    = 47_u8
        ESP    = 50_u8
        AH     = 51_u8
        ICMPV6 = 58_u8
        OSPF   = 89_u8
        SCTP   = 132_u8
      end

      # Known IPv4 option codes
      module IpOptionCode
        EOOL       = 0_u8   # End of Options List
        NOP        = 1_u8   # No Operation (padding)
        SEC        = 130_u8 # Security
        LSRR       = 131_u8 # Loose Source and Record Route
        TS         = 68_u8  # Internet Timestamp
        RR         = 7_u8   # Record Route
        SSRR       = 137_u8 # Strict Source and Record Route
        RA         = 148_u8 # Router Alert
      end

      class IPv4Dissector < Dissector
        def protocol : Protocol
          Protocol::IPv4
        end

        def name : String
          "IPv4"
        end

        # Computes the RFC 1071 Internet Checksum over a byte slice
        def self.calculate_checksum(header_bytes : Bytes) : UInt16
          sum = 0_u32
          i = 0
          len = header_bytes.size

          while i + 1 < len
            word = (header_bytes[i].to_u32 << 8) | header_bytes[i + 1].to_u32
            sum += word
            i += 2
          end

          # Add leftover odd byte if any
          if i < len
            sum += (header_bytes[i].to_u32 << 8)
          end

          # Fold 32-bit sum into 16 bits
          while (sum >> 16) > 0
            sum = (sum & 0xFFFF_u32) + (sum >> 16)
          end

          (~sum & 0xFFFF_u32).to_u16
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 20_u32
            errors << "Truncated IPv4 datagram: #{available} bytes available, minimum 20 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          version_ihl = data[start]
          version = version_ihl >> 4
          ihl = (version_ihl & 0x0F_u8).to_u32
          hdr_len = ihl * 4_u32

          if version != 4_u8
            errors << "Invalid IPv4 version #{version}"
          end

          if ihl < 5_u32
            errors << "Invalid IPv4 IHL #{ihl} (minimum 5 words = 20 bytes)"
            hdr_len = 20_u32
          end

          if available < hdr_len
            errors << "Truncated IPv4 header: #{available} bytes available, expected #{hdr_len}"
            hdr_len = available
          end

          dscp_ecn = data[start + 1]
          dscp = dscp_ecn >> 2
          ecn = dscp_ecn & 0x03_u8

          total_length = (data[start + 2].to_u16 << 8) | data[start + 3].to_u16
          identification = (data[start + 4].to_u16 << 8) | data[start + 5].to_u16

          flags_frag = (data[start + 6].to_u16 << 8) | data[start + 7].to_u16
          reserved_flag = (flags_frag & 0x8000_u16) != 0_u16
          df_flag = (flags_frag & 0x4000_u16) != 0_u16
          mf_flag = (flags_frag & 0x2000_u16) != 0_u16
          frag_offset = (flags_frag & 0x1FFF_u16) * 8_u16 # in bytes

          ttl = data[start + 8]
          proto_num = data[start + 9]
          checksum = (data[start + 10].to_u16 << 8) | data[start + 11].to_u16

          src_ip = Layer2::ArpDissector.format_ipv4(data[start + 12, 4])
          dst_ip = Layer2::ArpDissector.format_ipv4(data[start + 16, 4])

          fields["ip.version"] = version.to_u32
          fields["ip.hdr_len"] = hdr_len
          fields["ip.dscp"] = dscp.to_u32
          fields["ip.ecn"] = ecn.to_u32
          fields["ip.total_len"] = total_length.to_u32
          fields["ip.id"] = identification.to_u32
          fields["ip.flags.res"] = reserved_flag
          fields["ip.flags.df"] = df_flag
          fields["ip.flags.mf"] = mf_flag
          fields["ip.frag_offset"] = frag_offset.to_u32
          fields["ip.ttl"] = ttl.to_u32
          fields["ip.proto"] = proto_num.to_u32
          fields["ip.checksum"] = checksum.to_u32
          fields["ip.src"] = src_ip
          fields["ip.dst"] = dst_ip

          # Verify header checksum (excluding options to remain robust against corrupted options)
          if hdr_len <= available
            calc_csum = IPv4Dissector.calculate_checksum(data[start, hdr_len.to_i32])
            fields["ip.checksum_valid"] = (calc_csum == 0_u16)
          end

          # Parse optional header options if present (IHL > 5)
          if ihl > 5_u32 && hdr_len <= available
            opt_offset = start + 20
            opt_end = start + hdr_len.to_i32
            opt_names = [] of String

            while opt_offset < opt_end
              opt_code = data[opt_offset]
              break if opt_code == IpOptionCode::EOOL

              if opt_code == IpOptionCode::NOP
                opt_offset += 1
                next
              end

              break if opt_offset + 1 >= opt_end
              opt_len = data[opt_offset + 1].to_i32
              break if opt_len < 2 || opt_offset + opt_len > opt_end

              case opt_code
              when IpOptionCode::RR   then opt_names << "Record Route"
              when IpOptionCode::TS   then opt_names << "Timestamp"
              when IpOptionCode::RA   then opt_names << "Router Alert"
              when IpOptionCode::LSRR then opt_names << "Loose Source Route"
              when IpOptionCode::SSRR then opt_names << "Strict Source Route"
              else opt_names << "Option 0x#{opt_code.to_s(16)}"
              end

              opt_offset += opt_len
            end

            fields["ip.options"] = opt_names.join(", ") unless opt_names.empty?
          end

          # Compute payload boundaries
          payload_offset = offset + hdr_len
          # Respect IP total_length if packet capture length is larger (e.g. Ethernet padding)
          wire_payload_len = if total_length >= hdr_len
                               Math.min((total_length - hdr_len).to_u32, available - hdr_len)
                             else
                               available - hdr_len
                             end

          # Demultiplex to Layer 4
          # If datagram is a non-initial fragment, transport header cannot be reliably dissected directly
          next_proto : Protocol? = if frag_offset > 0_u16
                                     nil
                                   else
                                     case proto_num
                                     when IpProtocol::TCP    then Protocol::Tcp
                                     when IpProtocol::UDP    then Protocol::Udp
                                     when IpProtocol::ICMP   then Protocol::Icmp
                                     when IpProtocol::ICMPV6 then Protocol::Icmpv6
                                     else nil
                                     end
                                   end

          DissectResult.new(
            protocol: protocol,
            payload_offset: payload_offset,
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
