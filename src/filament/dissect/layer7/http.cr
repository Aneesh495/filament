# =============================================================================
# http.cr - Hypertext Transfer Protocol version 1.1 (RFC 7230 / RFC 9112)
# =============================================================================
#
# Implements RFC 7230 / RFC 9112 stream parsing for HTTP/1.1 requests and
# responses, structured header table extraction, and RFC 7230 chunked
# transfer encoding boundary decoding.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"

module Filament
  module Dissect
    module Layer7
      class HttpDissector < Dissector
        def protocol : Protocol
          Protocol::Http
        end

        def name : String
          "HTTP/1.1"
        end

        # Fast heuristic to check if ASCII slice starts with standard HTTP request method
        def self.request?(slice : Bytes) : Bool
          methods = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "]
          methods.any? do |m|
            slice.size >= m.bytesize && slice[0, m.bytesize] == m.to_slice
          end
        end

        # Fast heuristic to check if ASCII slice starts with HTTP response status line
        def self.response?(slice : Bytes) : Bool
          prefix = "HTTP/1."
          slice.size >= prefix.bytesize && slice[0, prefix.bytesize] == prefix.to_slice
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 4_u32
            errors << "Truncated HTTP payload: #{available} bytes available"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          slice = data[offset.to_i32, available.to_i32]
          text = String.new(slice)

          # Find end of HTTP headers (\r\n\r\n or \n\n)
          header_end_idx = text.index("\r\n\r\n")
          separator_len = 4
          if header_end_idx.nil?
            header_end_idx = text.index("\n\n")
            separator_len = 2
          end

          header_text = header_end_idx ? text[0, header_end_idx] : text
          body_offset = header_end_idx ? (offset + header_end_idx.to_u32 + separator_len.to_u32) : data.size.to_u32
          body_len = data.size.to_u32 - body_offset

          lines = header_text.split(/\r?\n/)
          return empty_result(data, offset, errors) if lines.empty?

          start_line = lines[0].strip

          if HttpDissector.request?(slice)
            parts = start_line.split(' ', 3)
            if parts.size >= 2
              fields["http.method"] = parts[0]
              fields["http.uri"] = parts[1]
              fields["http.version"] = parts[2]? || "HTTP/1.1"
            end
          elsif HttpDissector.response?(slice)
            parts = start_line.split(' ', 3)
            if parts.size >= 2
              fields["http.version"] = parts[0]
              status = parts[1].to_u16? || 0_u16
              fields["http.status_code"] = status
              fields["http.reason"] = parts[2]? || ""
            end
          else
            fields["http.type"] = "Continuation"
          end

          # Parse headers (lines 1..N)
          (1...lines.size).each do |line_idx|
            line = lines[line_idx]
            colon_idx = line.index(':')
            next unless colon_idx

            hname = line[0, colon_idx].strip.downcase
            hval = line[colon_idx + 1..].strip

            case hname
            when "host"             then fields["http.host"] = hval
            when "user-agent"       then fields["http.user_agent"] = hval
            when "content-type"     then fields["http.content_type"] = hval
            when "content-length"
              if cl = hval.to_u32?
                fields["http.content_length"] = cl
              end
            when "transfer-encoding" then fields["http.transfer_encoding"] = hval
            when "server"           then fields["http.server"] = hval
            when "location"         then fields["http.location"] = hval
            when "authorization"    then fields["http.authorization"] = "<redacted>"
            when "cookie"           then fields["http.cookie"] = hval
            when "set-cookie"       then fields["http.set_cookie"] = hval
            end
          end

          # Handle Chunked Transfer-Encoding if specified
          if fields["http.transfer_encoding"]? == "chunked" && body_len > 0_u32
            decode_chunked_body(data, body_offset, fields)
          end

          DissectResult.new(
            protocol: protocol,
            payload_offset: body_offset,
            payload_length: body_len,
            fields: fields,
            next_protocol: nil,
            errors: errors
          )
        end

        private def empty_result(data : Bytes, offset : UInt32, errors : Array(String)) : DissectResult
          DissectResult.new(
            protocol: protocol,
            payload_offset: data.size.to_u32,
            payload_length: 0_u32,
            fields: Hash(String, FieldValue).new,
            next_protocol: nil,
            errors: errors
          )
        end

        # Decodes hex chunk sizes for Chunked Transfer Encoding
        private def decode_chunked_body(data : Bytes, body_offset : UInt32, fields : Hash(String, FieldValue)) : Nil
          body_slice = data[body_offset.to_i32..]
          body_text = String.new(body_slice)
          first_crlf = body_text.index("\r\n")
          return unless first_crlf

          hex_str = body_text[0, first_crlf].split(';')[0].strip
          if chunk_size = hex_str.to_u32?(16)
            fields["http.chunk_size"] = chunk_size
          end
        end
      end
    end
  end
end
