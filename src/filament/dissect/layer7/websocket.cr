# =============================================================================
# websocket.cr - WebSocket Protocol framing (RFC 6455) dissector
# =============================================================================
#
# Implements RFC 6455 WebSocket frame parsing, extended length decoding,
# client-to-server 4-byte XOR unmasking, and control frame inspection
# (Ping, Pong, Close).
#
# Wire layout:
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-------+-+-------------+-------------------------------+
#  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
#  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
#  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
#  | |1|2|3|       |K|             |                               |
#  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
#  |     Extended payload length continued, if payload len == 127  |
#  + - - - - - - - - - - - - - - - +-------------------------------+
#  |                               |Masking-key, if MASK set to 1  |
#  +-------------------------------+-------------------------------+
#  | Masking-key (continued)       |          Payload Data         |
#  +-------------------------------- - - - - - - - - - - - - - - - +
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"

module Filament
  module Dissect
    module Layer7
      module WebSocketOpcode
        CONTINUATION = 0x0_u8
        TEXT         = 0x1_u8
        BINARY       = 0x2_u8
        CLOSE        = 0x8_u8
        PING         = 0x9_u8
        PONG         = 0xA_u8
      end

      class WebSocketDissector < Dissector
        def protocol : Protocol
          Protocol::WebSocket
        end

        def name : String
          "WebSocket"
        end

        # Unmasks payload bytes in-place or into new buffer using 4-byte XOR key
        def self.unmask(payload : Bytes, mask_key : Bytes) : Bytes
          return payload if mask_key.size < 4
          out = Bytes.new(payload.size)
          payload.size.times do |i|
            out[i] = payload[i] ^ mask_key[i % 4]
          end
          out
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 2_u32
            errors << "Truncated WebSocket frame: #{available} bytes available, 2 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          byte0 = data[start]
          byte1 = data[start + 1]

          fin = (byte0 & 0x80_u8) != 0_u8
          rsv1 = (byte0 & 0x40_u8) != 0_u8
          rsv2 = (byte0 & 0x20_u8) != 0_u8
          rsv3 = (byte0 & 0x10_u8) != 0_u8
          opcode = byte0 & 0x0F_u8

          is_masked = (byte1 & 0x80_u8) != 0_u8
          basic_len = (byte1 & 0x7F_u8).to_u64

          cursor = start + 2
          payload_len = basic_len

          if basic_len == 126_u64
            if cursor + 2 > start + available.to_i32
              errors << "Truncated 16-bit extended length"
              payload_len = 0_u64
            else
              payload_len = ((data[cursor].to_u64 << 8) | data[cursor + 1].to_u64)
              cursor += 2
            end
          elsif basic_len == 127_u64
            if cursor + 8 > start + available.to_i32
              errors << "Truncated 64-bit extended length"
              payload_len = 0_u64
            else
              val = 0_u64
              8.times do |b|
                val = (val << 8) | data[cursor + b].to_u64
              end
              payload_len = val
              cursor += 8
            end
          end

          mask_key : Bytes? = nil
          if is_masked
            if cursor + 4 <= start + available.to_i32
              mask_key = data[cursor, 4]
              cursor += 4
            else
              errors << "Truncated masking key"
            end
          end

          fields["ws.fin"] = fin
          fields["ws.opcode"] = opcode.to_u32
          fields["ws.masked"] = is_masked
          fields["ws.payload_len"] = payload_len

          opcode_name = case opcode
                        when WebSocketOpcode::CONTINUATION then "Continuation"
                        when WebSocketOpcode::TEXT         then "Text"
                        when WebSocketOpcode::BINARY       then "Binary"
                        when WebSocketOpcode::CLOSE        then "Connection Close"
                        when WebSocketOpcode::PING         then "Ping"
                        when WebSocketOpcode::PONG         then "Pong"
                        else                                    "Opcode #{opcode}"
                        end
          fields["ws.opcode_name"] = opcode_name

          # Unmask and decode text payload sample if opcode is Text
          data_start = cursor
          actual_payload_bytes = Math.min(payload_len.to_i32, (start + available.to_i32) - data_start)

          if actual_payload_bytes > 0 && data_start + actual_payload_bytes <= data.size
            raw_payload = data[data_start, actual_payload_bytes]
            clean_payload = if is_masked && mask_key
                              WebSocketDissector.unmask(raw_payload, mask_key)
                            else
                              raw_payload
                            end

            if opcode == WebSocketOpcode::TEXT
              # Truncate text representation to 256 characters for summary
              sample_len = Math.min(clean_payload.size, 256)
              text_sample = String.new(clean_payload[0, sample_len])
              fields["ws.text_sample"] = text_sample
            elsif opcode == WebSocketOpcode::CLOSE && clean_payload.size >= 2
              code = (clean_payload[0].to_u16 << 8) | clean_payload[1].to_u16
              fields["ws.close_code"] = code.to_u32
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
      end
    end
  end
end
