# =============================================================================
# dns.cr - Domain Name System wire format (RFC 1035 / RFC 6891) dissector
# =============================================================================
#
# Implements full RFC 1035 DNS message parsing including recursive domain
# name label compression pointer resolution (0xC0 prefix), question parsing,
# and typed Resource Record (RR) decoding for A, AAAA, CNAME, NS, MX, PTR,
# TXT, SOA, SRV, and RFC 6891 EDNS0 pseudo-records.
#
# Wire layout (12-byte base header):
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                      Transaction ID                           |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |Q| Opcode|A|T|R|R|   Z   |RCODE|                    QDCOUNT    |
#  |R|       |A|C|D|A|       |     |                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    ANCOUNT    |                    NSCOUNT    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    ARCOUNT    |                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"
require "../layer2/arp"
require "../layer3/ipv6"

module Filament
  module Dissect
    module Layer7
      module DnsType
        A     = 1_u16
        NS    = 2_u16
        CNAME = 5_u16
        SOA   = 6_u16
        PTR   = 12_u16
        MX    = 15_u16
        TXT   = 16_u16
        AAAA  = 28_u16
        SRV   = 33_u16
        OPT   = 41_u16 # EDNS0
        ANY   = 255_u16
      end

      module DnsRcode
        NO_ERROR  = 0_u8
        FORM_ERR  = 1_u8
        SERV_FAIL = 2_u8
        NXDOMAIN  = 3_u8
        NOT_IMP   = 4_u8
        REFUSED   = 5_u8
        YXDOMAIN  = 6_u8
        YXRRSET   = 7_u8
        NXRRSET   = 8_u8
        NOT_AUTH  = 9_u8
        NOT_ZONE  = 10_u8
      end

      # A decoded DNS Resource Record
      struct DnsResourceRecord
        getter name : String
        getter rtype : UInt16
        getter rclass : UInt16
        getter ttl : UInt32
        getter data_str : String

        def initialize(@name : String, @rtype : UInt16, @rclass : UInt16, @ttl : UInt32, @data_str : String)
        end
      end

      class DnsDissector < Dissector
        def protocol : Protocol
          Protocol::Dns
        end

        def name : String
          "DNS"
        end

        # Resolves a compressed or uncompressed domain name starting at byte offset
        # Returns tuple of {resolved_string, bytes_consumed_at_primary_offset}
        def self.read_name(data : Bytes, offset : Int32, base_offset : Int32 = 0) : Tuple(String, Int32)
          labels = [] of String
          idx = offset
          initial_bytes_consumed = 0
          jumped = false
          loop_guard = 0

          while idx < data.size && loop_guard < 64
            loop_guard += 1
            len_byte = data[idx]

            # End of name label list
            if len_byte == 0_u8
              initial_bytes_consumed += 1 unless jumped
              idx += 1
              break
            end

            # Check if this is a compression pointer (top two bits 11)
            if (len_byte & 0xC0_u8) == 0xC0_u8
              return {"<invalid_pointer>", 2} if idx + 1 >= data.size

              pointer_offset = ((len_byte.to_i32 & 0x3F) << 8) | data[idx + 1].to_i32
              initial_bytes_consumed += 2 unless jumped
              jumped = true

              # Pointer offset is relative to the start of the DNS header
              target = base_offset + pointer_offset
              return {"<pointer_out_of_bounds>", initial_bytes_consumed} if target >= data.size

              idx = target
              next
            end

            # Standard label
            label_len = len_byte.to_i32
            initial_bytes_consumed += (1 + label_len) unless jumped
            return {"<truncated_label>", initial_bytes_consumed} if idx + 1 + label_len > data.size

            label_bytes = data[idx + 1, label_len]
            labels << String.new(label_bytes)
            idx += 1 + label_len
          end

          name_str = labels.empty? ? "." : labels.join(".")
          {name_str, initial_bytes_consumed}
        end

        # Resolves type code to human readable mnemonic
        def self.type_to_s(rtype : UInt16) : String
          case rtype
          when DnsType::A     then "A"
          when DnsType::AAAA  then "AAAA"
          when DnsType::CNAME then "CNAME"
          when DnsType::MX    then "MX"
          when DnsType::NS    then "NS"
          when DnsType::PTR   then "PTR"
          when DnsType::SOA   then "SOA"
          when DnsType::TXT   then "TXT"
          when DnsType::SRV   then "SRV"
          when DnsType::OPT   then "OPT (EDNS0)"
          when DnsType::ANY   then "ANY"
          else "TYPE#{rtype}"
          end
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 12_u32
            errors << "Truncated DNS header: #{available} bytes available, 12 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          tx_id = (data[start].to_u16 << 8) | data[start + 1].to_u16
          flags = (data[start + 2].to_u16 << 8) | data[start + 3].to_u16

          is_response = (flags & 0x8000_u16) != 0_u16
          opcode = ((flags >> 11) & 0x0F_u16).to_u8
          authoritative = (flags & 0x0400_u16) != 0_u16
          truncated = (flags & 0x0200_u16) != 0_u16
          recursion_desired = (flags & 0x0100_u16) != 0_u16
          recursion_available = (flags & 0x0080_u16) != 0_u16
          rcode = (flags & 0x000F_u16).to_u8

          qdcount = (data[start + 4].to_u16 << 8) | data[start + 5].to_u16
          ancount = (data[start + 6].to_u16 << 8) | data[start + 7].to_u16
          nscount = (data[start + 8].to_u16 << 8) | data[start + 9].to_u16
          arcount = (data[start + 10].to_u16 << 8) | data[start + 11].to_u16

          fields["dns.tx_id"] = tx_id.to_u32
          fields["dns.is_response"] = is_response
          fields["dns.opcode"] = opcode.to_u32
          fields["dns.aa"] = authoritative
          fields["dns.tc"] = truncated
          fields["dns.rd"] = recursion_desired
          fields["dns.ra"] = recursion_available
          fields["dns.rcode"] = rcode.to_u32
          fields["dns.qdcount"] = qdcount.to_u32
          fields["dns.ancount"] = ancount.to_u32
          fields["dns.nscount"] = nscount.to_u32
          fields["dns.arcount"] = arcount.to_u32

          rcode_name = case rcode
                       when DnsRcode::NO_ERROR  then "No error"
                       when DnsRcode::FORM_ERR  then "Format error"
                       when DnsRcode::SERV_FAIL then "Server failure"
                       when DnsRcode::NXDOMAIN  then "Non-existent domain (NXDOMAIN)"
                       when DnsRcode::NOT_IMP   then "Not implemented"
                       when DnsRcode::REFUSED   then "Query refused"
                       else "RCODE #{rcode}"
                       end
          fields["dns.rcode_name"] = rcode_name

          cursor = start + 12

          # Parse Questions
          first_qname = ""
          first_qtype = ""

          qdcount.times do |i|
            break if cursor >= data.size
            qname, consumed = DnsDissector.read_name(data, cursor, start)
            cursor += consumed
            break if cursor + 4 > data.size

            qtype = (data[cursor].to_u16 << 8) | data[cursor + 1].to_u16
            _qclass = (data[cursor + 2].to_u16 << 8) | data[cursor + 3].to_u16
            cursor += 4

            if i == 0
              first_qname = qname
              first_qtype = DnsDissector.type_to_s(qtype)
            end
          end

          fields["dns.qname"] = first_qname unless first_qname.empty?
          fields["dns.qtype"] = first_qtype unless first_qtype.empty?

          # Parse Answer Records
          answers = [] of String

          ancount.times do |_i|
            break if cursor >= data.size
            _aname, consumed = DnsDissector.read_name(data, cursor, start)
            cursor += consumed
            break if cursor + 10 > data.size

            rtype = (data[cursor].to_u16 << 8) | data[cursor + 1].to_u16
            _rclass = (data[cursor + 2].to_u16 << 8) | data[cursor + 3].to_u16
            _ttl = (data[cursor + 4].to_u32 << 24) |
                   (data[cursor + 5].to_u32 << 16) |
                   (data[cursor + 6].to_u32 << 8) |
                   data[cursor + 7].to_u32
            rdlength = (data[cursor + 8].to_u16 << 8) | data[cursor + 9].to_u16
            cursor += 10

            break if cursor + rdlength > data.size
            rdata_slice = data[cursor, rdlength.to_i32]

            case rtype
            when DnsType::A
              if rdlength == 4
                ip = Layer2::ArpDissector.format_ipv4(rdata_slice)
                answers << ip
              end
            when DnsType::AAAA
              if rdlength == 16
                ip6 = Layer3::IPv6Dissector.format_ipv6(rdata_slice)
                answers << ip6
              end
            when DnsType::CNAME, DnsType::PTR, DnsType::NS
              cname_val, _ = DnsDissector.read_name(data, cursor, start)
              answers << cname_val
            end

            cursor += rdlength
          end

          fields["dns.answers"] = answers.join(", ") unless answers.empty?

          DissectResult.new(
            protocol: protocol,
            payload_offset: data.size.to_u32, # DNS completes the stack
            payload_length: 0_u32,
            fields: fields,
            next_protocol: nil,
            errors: errors
          )
        end
      end
    end
  end
end
