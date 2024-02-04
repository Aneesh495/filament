# =============================================================================
# dhcp.cr - Dynamic Host Configuration Protocol (RFC 2131 / RFC 2132) dissector
# =============================================================================
#
# Implements BOOTP / DHCP message decoding and RFC 2132 TLV options parsing.
# Extracts client hardware identities, leased network parameters, DNS servers,
# router gateways, and lease durations.
#
# Wire layout (Fixed 240-byte BOOTP header + Magic Cookie + Options):
#   - op (8 bits: 1=BOOTREQUEST, 2=BOOTREPLY)
#   - htype (8 bits: 1=Ethernet)
#   - hlen (8 bits: 6)
#   - hops (8 bits)
#   - xid (32 bits, Transaction ID)
#   - secs (16 bits)
#   - flags (16 bits: Broadcast bit)
#   - ciaddr (Client IP, 4 bytes)
#   - yiaddr ("Your" client IP, 4 bytes)
#   - siaddr (Server IP, 4 bytes)
#   - giaddr (Gateway / Relay Agent IP, 4 bytes)
#   - chaddr (Client Hardware MAC, 16 bytes)
#   - sname (Server host name, 64 bytes)
#   - file (Boot file name, 128 bytes)
#   - Magic Cookie (4 bytes: 0x63, 0x82, 0x53, 0x63)
#   - Options (Variable length)
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"
require "../layer2/arp"
require "../layer2/ethernet"

module Filament
  module Dissect
    module Layer7
      module DhcpMessageType
        DISCOVER = 1_u8
        OFFER    = 2_u8
        REQUEST  = 3_u8
        DECLINE  = 4_u8
        ACK      = 5_u8
        NAK      = 6_u8
        RELEASE  = 7_u8
        INFORM   = 8_u8
      end

      module DhcpOptionCode
        PAD            =   0_u8
        SUBNET_MASK    =   1_u8
        ROUTER         =   3_u8
        DNS_SERVERS    =   6_u8
        HOSTNAME       =  12_u8
        DOMAIN_NAME    =  15_u8
        REQUESTED_IP   =  50_u8
        LEASE_TIME     =  51_u8
        MESSAGE_TYPE   =  53_u8
        SERVER_ID      =  54_u8
        PARAM_REQ_LIST =  55_u8
        END_OF_OPTIONS = 255_u8
      end

      class DhcpDissector < Dissector
        def protocol : Protocol
          Protocol::Dhcp
        end

        def name : String
          "DHCP"
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 240_u32
            errors << "Truncated BOOTP/DHCP header: #{available} bytes available, 240 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          op = data[start]
          htype = data[start + 1]
          hlen = data[start + 2]
          _hops = data[start + 3]
          xid = (data[start + 4].to_u32 << 24) |
                (data[start + 5].to_u32 << 16) |
                (data[start + 6].to_u32 << 8) |
                data[start + 7].to_u32

          secs = (data[start + 8].to_u16 << 8) | data[start + 9].to_u16
          flags = (data[start + 10].to_u16 << 8) | data[start + 11].to_u16
          broadcast = (flags & 0x8000_u16) != 0_u16

          ciaddr = Layer2::ArpDissector.format_ipv4(data[start + 12, 4])
          yiaddr = Layer2::ArpDissector.format_ipv4(data[start + 16, 4])
          siaddr = Layer2::ArpDissector.format_ipv4(data[start + 20, 4])
          giaddr = Layer2::ArpDissector.format_ipv4(data[start + 24, 4])

          # Client MAC from chaddr
          chaddr = if hlen == 6_u8
                     Layer2::EthernetDissector.format_mac(data[start + 28, 6])
                   else
                     "unknown"
                   end

          fields["dhcp.op"] = op.to_u32
          fields["dhcp.htype"] = htype.to_u32
          fields["dhcp.hlen"] = hlen.to_u32
          fields["dhcp.xid"] = xid
          fields["dhcp.secs"] = secs.to_u32
          fields["dhcp.broadcast"] = broadcast
          fields["dhcp.ciaddr"] = ciaddr
          fields["dhcp.yiaddr"] = yiaddr
          fields["dhcp.siaddr"] = siaddr
          fields["dhcp.giaddr"] = giaddr
          fields["dhcp.chaddr"] = chaddr

          # Check Magic Cookie (offset 236 to 239)
          if available >= 240_u32
            cookie = (data[start + 236].to_u32 << 24) |
                     (data[start + 237].to_u32 << 16) |
                     (data[start + 238].to_u32 << 8) |
                     data[start + 239].to_u32

            if cookie == 0x63825363_u32
              fields["dhcp.has_magic_cookie"] = true
              parse_options(data, start + 240, available.to_i32 - 240, fields)
            end
          end

          DissectResult.new(
            protocol: protocol,
            payload_offset: data.size.to_u32,
            payload_length: 0_u32,
            fields: fields,
            next_protocol: nil,
            errors: errors
          )
        end

        # Parses RFC 2132 DHCP Options
        private def parse_options(data : Bytes, offset : Int32, len : Int32, fields : Hash(String, FieldValue)) : Nil
          idx = offset
          limit = offset + len

          while idx < limit
            code = data[idx]
            break if code == DhcpOptionCode::END_OF_OPTIONS

            if code == DhcpOptionCode::PAD
              idx += 1
              next
            end

            break if idx + 1 >= limit
            opt_len = data[idx + 1].to_i32
            break if idx + 2 + opt_len > limit

            opt_data = data[idx + 2, opt_len]

            case code
            when DhcpOptionCode::MESSAGE_TYPE
              if opt_len >= 1
                msg_type = opt_data[0]
                fields["dhcp.msg_type"] = msg_type.to_u32
                type_name = case msg_type
                            when DhcpMessageType::DISCOVER then "Discover"
                            when DhcpMessageType::OFFER    then "Offer"
                            when DhcpMessageType::REQUEST  then "Request"
                            when DhcpMessageType::DECLINE  then "Decline"
                            when DhcpMessageType::ACK      then "ACK"
                            when DhcpMessageType::NAK      then "NAK"
                            when DhcpMessageType::RELEASE  then "Release"
                            when DhcpMessageType::INFORM   then "Inform"
                            else                                "Type #{msg_type}"
                            end
                fields["dhcp.msg_type_name"] = type_name
              end
            when DhcpOptionCode::SUBNET_MASK
              if opt_len == 4
                fields["dhcp.subnet_mask"] = Layer2::ArpDissector.format_ipv4(opt_data)
              end
            when DhcpOptionCode::ROUTER
              if opt_len >= 4
                fields["dhcp.router"] = Layer2::ArpDissector.format_ipv4(opt_data[0, 4])
              end
            when DhcpOptionCode::DNS_SERVERS
              dns_list = [] of String
              (opt_len // 4).times do |i|
                dns_list << Layer2::ArpDissector.format_ipv4(opt_data[i * 4, 4])
              end
              fields["dhcp.dns_servers"] = dns_list.join(", ") unless dns_list.empty?
            when DhcpOptionCode::HOSTNAME
              fields["dhcp.hostname"] = String.new(opt_data)
            when DhcpOptionCode::DOMAIN_NAME
              fields["dhcp.domain_name"] = String.new(opt_data)
            when DhcpOptionCode::REQUESTED_IP
              if opt_len == 4
                fields["dhcp.requested_ip"] = Layer2::ArpDissector.format_ipv4(opt_data)
              end
            when DhcpOptionCode::LEASE_TIME
              if opt_len == 4
                lease = (opt_data[0].to_u32 << 24) |
                        (opt_data[1].to_u32 << 16) |
                        (opt_data[2].to_u32 << 8) |
                        opt_data[3].to_u32
                fields["dhcp.lease_time"] = lease
              end
            when DhcpOptionCode::SERVER_ID
              if opt_len == 4
                fields["dhcp.server_id"] = Layer2::ArpDissector.format_ipv4(opt_data)
              end
            end

            idx += 2 + opt_len
          end
        end
      end
    end
  end
end
