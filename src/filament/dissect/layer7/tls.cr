# =============================================================================
# tls.cr - Transport Layer Security (RFC 5246 TLS 1.2 / RFC 8446 TLS 1.3)
# =============================================================================
#
# Implements TLS Record Layer decoding and cryptographic Handshake message
# inspection. Extracts plaintext handshake metadata before encryption begins:
#
#   - Server Name Indication (SNI) hostnames
#   - Application-Layer Protocol Negotiation (ALPN) protocol lists (h2, http/1.1)
#   - Advertised and selected cipher suite identifiers
#   - Supported TLS versions (distinguishing TLS 1.2 from TLS 1.3)
#   - Supported elliptic curves / key exchange groups (X25519, secp256r1)
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"

module Filament
  module Dissect
    module Layer7
      module TlsContentType
        CHANGE_CIPHER_SPEC = 20_u8
        ALERT              = 21_u8
        HANDSHAKE          = 22_u8
        APPLICATION_DATA   = 23_u8
        HEARTBEAT          = 24_u8
      end

      module TlsHandshakeType
        HELLO_REQUEST       = 0_u8
        CLIENT_HELLO        = 1_u8
        SERVER_HELLO        = 2_u8
        NEW_SESSION_TICKET  = 4_u8
        END_OF_EARLY_DATA   = 5_u8
        ENCRYPTED_EXTS      = 8_u8
        CERTIFICATE         = 11_u8
        SERVER_KEY_EXCHANGE = 12_u8
        CERT_REQUEST        = 13_u8
        SERVER_HELLO_DONE   = 14_u8
        CERT_VERIFY         = 15_u8
        CLIENT_KEY_EXCHANGE = 16_u8
        FINISHED            = 20_u8
      end

      module TlsExtensionType
        SERVER_NAME      = 0_u16  # SNI (RFC 6066)
        SUPPORTED_GROUPS = 10_u16 # Elliptic curves (RFC 8422)
        SIGNATURE_ALGS   = 13_u16 # (RFC 5246)
        ALPN             = 16_u16 # Application-Layer Protocol Negotiation (RFC 7301)
        SUPPORTED_VERS   = 43_u16 # Supported Versions (RFC 8446 TLS 1.3)
        KEY_SHARE        = 51_u16 # Key Share (RFC 8446)
      end

      class TlsDissector < Dissector
        def protocol : Protocol
          Protocol::Tls
        end

        def name : String
          "TLS"
        end

        # Translates 16-bit TLS version codes to canonical strings
        def self.version_to_s(ver : UInt16) : String
          case ver
          when 0x0300_u16 then "SSL 3.0"
          when 0x0301_u16 then "TLS 1.0"
          when 0x0302_u16 then "TLS 1.1"
          when 0x0303_u16 then "TLS 1.2"
          when 0x0304_u16 then "TLS 1.3"
          else "0x#{ver.to_s(16)}"
          end
        end

        # Resolves common IANA cipher suite identifiers
        def self.cipher_suite_to_s(cs : UInt16) : String
          case cs
          when 0x1301_u16 then "TLS_AES_128_GCM_SHA256"
          when 0x1302_u16 then "TLS_AES_256_GCM_SHA384"
          when 0x1303_u16 then "TLS_CHACHA20_POLY1305_SHA256"
          when 0xC02F_u16 then "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
          when 0xC030_u16 then "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
          when 0xC02B_u16 then "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
          when 0xC02C_u16 then "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
          when 0xCCA8_u16 then "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
          when 0xCCA9_u16 then "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
          when 0x009C_u16 then "TLS_RSA_WITH_AES_128_GCM_SHA256"
          when 0x009D_u16 then "TLS_RSA_WITH_AES_256_GCM_SHA384"
          else "0x#{cs.to_s(16).rjust(4, '0')}"
          end
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 5_u32
            errors << "Truncated TLS record header: #{available} bytes available, 5 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          content_type = data[start]
          legacy_version = (data[start + 1].to_u16 << 8) | data[start + 2].to_u16
          record_length = (data[start + 3].to_u16 << 8) | data[start + 4].to_u16

          fields["tls.content_type"] = content_type.to_u32
          fields["tls.legacy_version"] = TlsDissector.version_to_s(legacy_version)
          fields["tls.record_length"] = record_length.to_u32

          type_str = case content_type
                     when TlsContentType::CHANGE_CIPHER_SPEC then "Change Cipher Spec"
                     when TlsContentType::ALERT              then "Alert"
                     when TlsContentType::HANDSHAKE          then "Handshake"
                     when TlsContentType::APPLICATION_DATA   then "Application Data"
                     when TlsContentType::HEARTBEAT          then "Heartbeat"
                     else "ContentType #{content_type}"
                     end
          fields["tls.type"] = type_str

          # If this is a Handshake record, inspect handshake payload
          if content_type == TlsContentType::HANDSHAKE && available >= 9_u32
            dissect_handshake(data, start + 5, Math.min(record_length.to_i32, available.to_i32 - 5), fields)
          end

          fields["tls.version"] ||= TlsDissector.version_to_s(legacy_version)

          payload_offset = offset + 5_u32
          payload_len = Math.min(record_length.to_u32, available - 5_u32)

          DissectResult.new(
            protocol: protocol,
            payload_offset: payload_offset,
            payload_length: payload_len,
            fields: fields,
            next_protocol: nil,
            errors: errors
          )
        end

        # Dissects unencrypted handshake messages (ClientHello and ServerHello)
        private def dissect_handshake(data : Bytes, offset : Int32, len : Int32, fields : Hash(String, FieldValue)) : Nil
          return if len < 4

          msg_type = data[offset]
          msg_len = (data[offset + 1].to_i32 << 16) | (data[offset + 2].to_i32 << 8) | data[offset + 3].to_i32

          fields["tls.handshake_type"] = msg_type.to_u32

          case msg_type
          when TlsHandshakeType::CLIENT_HELLO
            fields["tls.handshake_name"] = "Client Hello"
            dissect_client_hello(data, offset + 4, len - 4, fields)
          when TlsHandshakeType::SERVER_HELLO
            fields["tls.handshake_name"] = "Server Hello"
            dissect_server_hello(data, offset + 4, len - 4, fields)
          when TlsHandshakeType::CERTIFICATE
            fields["tls.handshake_name"] = "Certificate"
          else
            fields["tls.handshake_name"] = "Handshake #{msg_type}"
          end
        end

        # Parses ClientHello structure
        private def dissect_client_hello(data : Bytes, offset : Int32, len : Int32, fields : Hash(String, FieldValue)) : Nil
          return if len < 34 # 2 ver + 32 random

          client_ver = (data[offset].to_u16 << 8) | data[offset + 1].to_u16
          cursor = offset + 34

          # Session ID
          return if cursor >= offset + len
          sess_id_len = data[cursor].to_i32
          cursor += 1 + sess_id_len

          # Cipher Suites
          return if cursor + 2 > offset + len
          cs_len = (data[cursor].to_i32 << 8) | data[cursor + 1].to_i32
          cursor += 2

          ciphers = [] of String
          cs_end = cursor + cs_len
          while cursor + 2 <= cs_end && cursor + 2 <= offset + len
            cs_id = (data[cursor].to_u16 << 8) | data[cursor + 1].to_u16
            ciphers << TlsDissector.cipher_suite_to_s(cs_id)
            cursor += 2
          end

          fields["tls.cipher_suites"] = ciphers.join(", ") unless ciphers.empty?
          cursor = cs_end

          # Compression Methods
          return if cursor >= offset + len
          comp_len = data[cursor].to_i32
          cursor += 1 + comp_len

          # Extensions
          return if cursor + 2 > offset + len
          ext_total_len = (data[cursor].to_i32 << 8) | data[cursor + 1].to_i32
          cursor += 2

          ext_end = cursor + ext_total_len
          parse_extensions(data, cursor, Math.min(ext_end, offset + len), fields)
        end

        # Parses ServerHello structure
        private def dissect_server_hello(data : Bytes, offset : Int32, len : Int32, fields : Hash(String, FieldValue)) : Nil
          return if len < 34

          cursor = offset + 34
          return if cursor >= offset + len
          sess_id_len = data[cursor].to_i32
          cursor += 1 + sess_id_len

          return if cursor + 2 > offset + len
          selected_cipher = (data[cursor].to_u16 << 8) | data[cursor + 1].to_u16
          fields["tls.selected_cipher"] = TlsDissector.cipher_suite_to_s(selected_cipher)
          cursor += 3 # 2 cipher + 1 compression

          return if cursor + 2 > offset + len
          ext_len = (data[cursor].to_i32 << 8) | data[cursor + 1].to_i32
          cursor += 2
          parse_extensions(data, cursor, Math.min(cursor + ext_len, offset + len), fields)
        end

        # Parses TLS Extension records
        private def parse_extensions(data : Bytes, start_idx : Int32, end_idx : Int32, fields : Hash(String, FieldValue)) : Nil
          cursor = start_idx

          while cursor + 4 <= end_idx
            ext_type = (data[cursor].to_u16 << 8) | data[cursor + 1].to_u16
            ext_len = (data[cursor + 2].to_i32 << 8) | data[cursor + 3].to_i32
            ext_data_start = cursor + 4
            cursor += 4 + ext_len
            break if cursor > end_idx

            case ext_type
            when TlsExtensionType::SERVER_NAME
              parse_sni(data, ext_data_start, ext_len, fields)
            when TlsExtensionType::ALPN
              parse_alpn(data, ext_data_start, ext_len, fields)
            when TlsExtensionType::SUPPORTED_VERS
              parse_supported_versions(data, ext_data_start, ext_len, fields)
            end
          end
        end

        private def parse_sni(data : Bytes, offset : Int32, len : Int32, fields : Hash(String, FieldValue)) : Nil
          return if len < 5 # 2 list_len + 1 name_type + 2 name_len
          name_type = data[offset + 2]
          return unless name_type == 0_u8 # host_name

          name_len = (data[offset + 3].to_i32 << 8) | data[offset + 4].to_i32
          return if offset + 5 + name_len > data.size

          sni_str = String.new(data[offset + 5, name_len])
          fields["tls.sni"] = sni_str
        end

        private def parse_alpn(data : Bytes, offset : Int32, len : Int32, fields : Hash(String, FieldValue)) : Nil
          return if len < 2
          alpn_list_len = (data[offset].to_i32 << 8) | data[offset + 1].to_i32
          cursor = offset + 2
          limit = offset + 2 + alpn_list_len

          protocols = [] of String
          while cursor < limit && cursor < data.size
            proto_len = data[cursor].to_i32
            break if cursor + 1 + proto_len > data.size

            proto_str = String.new(data[cursor + 1, proto_len])
            protocols << proto_str
            cursor += 1 + proto_len
          end

          fields["tls.alpn"] = protocols.join(", ") unless protocols.empty?
        end

        private def parse_supported_versions(data : Bytes, offset : Int32, len : Int32, fields : Hash(String, FieldValue)) : Nil
          return if len < 2
          # In ServerHello, it's just 2 bytes for the selected version
          if len == 2
            ver = (data[offset].to_u16 << 8) | data[offset + 1].to_u16
            fields["tls.version"] = TlsDissector.version_to_s(ver)
          else
            # In ClientHello, 1 byte length followed by 2-byte version list
            list_len = data[offset].to_i32
            idx = offset + 1
            has_tls13 = false
            while idx + 2 <= offset + 1 + list_len && idx + 2 <= data.size
              ver = (data[idx].to_u16 << 8) | data[idx + 1].to_u16
              has_tls13 = true if ver == 0x0304_u16
              idx += 2
            end
            fields["tls.version"] = "TLS 1.3" if has_tls13
          end
        end
      end
    end
  end
end
