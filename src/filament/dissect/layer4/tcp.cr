# =============================================================================
# tcp.cr - Transmission Control Protocol (RFC 793 / RFC 9293) dissector
# =============================================================================
#
# Implements full RFC 793 / RFC 9293 TCP segment header decoding, bitflag
# decomposition, and comprehensive TCP option parsing (MSS, Window Scale,
# SACK Permitted, SACK blocks, and RFC 7323 High Performance Timestamps).
#
# Wire layout (20 to 60 bytes):
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |          Source Port          |       Destination Port        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Sequence Number                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Acknowledgment Number                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |  Data |       |C|E|U|A|P|R|S|F|                               |
#  | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
#  |       |       |R|E|G|K|H|T|N|N|                               |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |           Checksum            |         Urgent Pointer        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Options                    |    Padding    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"

module Filament
  module Dissect
    module Layer4
      # TCP Option Kind constants
      module TcpOptionKind
        EOL            =  0_u8 # End of Option List
        NOP            =  1_u8 # No-Operation (padding)
        MSS            =  2_u8 # Maximum Segment Size
        WINDOW_SCALE   =  3_u8 # Window Scale factor (RFC 7323)
        SACK_PERMITTED =  4_u8 # Selective ACK Permitted (RFC 2018)
        SACK           =  5_u8 # Selective ACK (RFC 2018)
        TIMESTAMPS     =  8_u8 # Timestamps (RFC 7323)
        FAST_OPEN      = 34_u8 # TCP Fast Open (RFC 7413)
      end

      # A single SACK edge boundary (Left Edge, Right Edge)
      struct SackEdge
        getter left : UInt32
        getter right : UInt32

        def initialize(@left : UInt32, @right : UInt32)
        end
      end

      class TcpDissector < Dissector
        def protocol : Protocol
          Protocol::Tcp
        end

        def name : String
          "TCP"
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 20_u32
            errors << "Truncated TCP header: #{available} bytes available, 20 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          src_port = (data[start].to_u16 << 8) | data[start + 1].to_u16
          dst_port = (data[start + 2].to_u16 << 8) | data[start + 3].to_u16

          seq = (data[start + 4].to_u32 << 24) |
                (data[start + 5].to_u32 << 16) |
                (data[start + 6].to_u32 << 8) |
                data[start + 7].to_u32

          ack = (data[start + 8].to_u32 << 24) |
                (data[start + 9].to_u32 << 16) |
                (data[start + 10].to_u32 << 8) |
                data[start + 11].to_u32

          offset_flags = (data[start + 12].to_u16 << 8) | data[start + 13].to_u16
          data_offset = ((offset_flags >> 12) & 0x0F_u16).to_u32 # 4-byte words
          hdr_len = data_offset * 4_u32

          if data_offset < 5_u32
            errors << "Invalid TCP data offset #{data_offset} (minimum 5 words = 20 bytes)"
            hdr_len = 20_u32
          end

          if available < hdr_len
            errors << "Truncated TCP options: #{available} bytes available, #{hdr_len} expected"
            hdr_len = available
          end

          # Flag bit decomposition
          cwr = (offset_flags & 0x0080_u16) != 0_u16
          ece = (offset_flags & 0x0040_u16) != 0_u16
          urg = (offset_flags & 0x0020_u16) != 0_u16
          ack_flag = (offset_flags & 0x0010_u16) != 0_u16
          psh = (offset_flags & 0x0008_u16) != 0_u16
          rst = (offset_flags & 0x0004_u16) != 0_u16
          syn = (offset_flags & 0x0002_u16) != 0_u16
          fin = (offset_flags & 0x0001_u16) != 0_u16

          window_size = (data[start + 14].to_u16 << 8) | data[start + 15].to_u16
          checksum = (data[start + 16].to_u16 << 8) | data[start + 17].to_u16
          urgent_ptr = (data[start + 18].to_u16 << 8) | data[start + 19].to_u16

          # Human readable flags representation
          flags_list = [] of String
          flags_list << "SYN" if syn
          flags_list << "FIN" if fin
          flags_list << "RST" if rst
          flags_list << "PSH" if psh
          flags_list << "ACK" if ack_flag
          flags_list << "URG" if urg
          flags_list << "ECE" if ece
          flags_list << "CWR" if cwr
          flags_str = flags_list.empty? ? "None" : flags_list.join(", ")

          fields["tcp.src_port"] = src_port
          fields["tcp.dst_port"] = dst_port
          fields["tcp.seq"] = seq
          fields["tcp.ack"] = ack
          fields["tcp.hdr_len"] = hdr_len
          fields["tcp.flags.syn"] = syn
          fields["tcp.flags.fin"] = fin
          fields["tcp.flags.rst"] = rst
          fields["tcp.flags.psh"] = psh
          fields["tcp.flags.ack"] = ack_flag
          fields["tcp.flags.urg"] = urg
          fields["tcp.flags.ece"] = ece
          fields["tcp.flags.cwr"] = cwr
          fields["tcp.flags_str"] = flags_str
          fields["tcp.window_size"] = window_size
          fields["tcp.checksum"] = checksum.to_u32
          fields["tcp.urgent_ptr"] = urgent_ptr.to_u32

          # Parse options if present (hdr_len > 20)
          if hdr_len > 20_u32 && hdr_len <= available
            opt_idx = start + 20
            opt_end = start + hdr_len.to_i32

            while opt_idx < opt_end
              kind = data[opt_idx]
              break if kind == TcpOptionKind::EOL

              if kind == TcpOptionKind::NOP
                opt_idx += 1
                next
              end

              break if opt_idx + 1 >= opt_end
              opt_len = data[opt_idx + 1].to_i32
              break if opt_len < 2 || opt_idx + opt_len > opt_end

              case kind
              when TcpOptionKind::MSS
                if opt_len == 4
                  mss = (data[opt_idx + 2].to_u16 << 8) | data[opt_idx + 3].to_u16
                  fields["tcp.options.mss"] = mss.to_u32
                end
              when TcpOptionKind::WINDOW_SCALE
                if opt_len == 3
                  wscale = data[opt_idx + 2]
                  fields["tcp.options.window_scale"] = wscale.to_u32
                end
              when TcpOptionKind::SACK_PERMITTED
                fields["tcp.options.sack_permitted"] = true
              when TcpOptionKind::TIMESTAMPS
                if opt_len == 10
                  tsval = (data[opt_idx + 2].to_u32 << 24) |
                          (data[opt_idx + 3].to_u32 << 16) |
                          (data[opt_idx + 4].to_u32 << 8) |
                          data[opt_idx + 5].to_u32
                  tsecr = (data[opt_idx + 6].to_u32 << 24) |
                          (data[opt_idx + 7].to_u32 << 16) |
                          (data[opt_idx + 8].to_u32 << 8) |
                          data[opt_idx + 9].to_u32
                  fields["tcp.options.tsval"] = tsval
                  fields["tcp.options.tsecr"] = tsecr
                end
              when TcpOptionKind::SACK
                edge_count = (opt_len - 2) // 8
                if edge_count >= 1
                  fields["tcp.options.sack_blocks"] = edge_count.to_u32
                end
              end

              opt_idx += opt_len
            end
          end

          payload_offset = offset + hdr_len
          payload_len = available - hdr_len

          # Demultiplex to Layer 7 protocols based on standard ports
          next_proto : Protocol? = case {src_port, dst_port}
          when {80_u16, _}, {_, 80_u16}, {8080_u16, _}, {_, 8080_u16}
            Protocol::Http
          when {443_u16, _}, {_, 443_u16}, {8443_u16, _}, {_, 8443_u16}
            Protocol::Tls
          when {25_u16, _}, {_, 25_u16}, {587_u16, _}, {_, 587_u16}
            Protocol::Smtp
          when {53_u16, _}, {_, 53_u16}
            Protocol::Dns
          else
            nil
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
