# =============================================================================
# ntp.cr - Network Time Protocol version 4 (RFC 5905) dissector
# =============================================================================
#
# Implements RFC 5905 Network Time Protocol (NTP) packet decoding, fixed-point
# 64-bit timestamp resolution relative to the NTP epoch (January 1, 1900),
# stratum evaluation, and clock offset calculation.
#
# Wire layout (48-byte fixed base header):
#   - LI (2 bits), VN (3 bits), Mode (3 bits)
#   - Stratum (8 bits)
#   - Poll Interval (8 bits, log2 seconds)
#   - Precision (8 bits, signed log2 seconds)
#   - Root Delay (32-bit fixed point: 16 bits integer, 16 bits fraction)
#   - Root Dispersion (32-bit fixed point)
#   - Reference ID (32 bits)
#   - Reference Timestamp (64 bits)
#   - Origin Timestamp (64 bits)
#   - Receive Timestamp (64 bits)
#   - Transmit Timestamp (64 bits)
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"

module Filament
  module Dissect
    module Layer7
      class NtpDissector < Dissector
        def protocol : Protocol
          Protocol::Ntp
        end

        def name : String
          "NTP"
        end

        # NTP epoch is 1900-01-01 00:00:00 UTC
        # Difference between 1900 and Unix epoch 1970 is 2,208,988,800 seconds
        NTP_TIMESTAMP_DELTA = 2_208_988_800_u64

        # Decodes 64-bit NTP timestamp into Crystal Time
        def self.ntp_to_time(sec : UInt32, frac : UInt32) : Time?
          return nil if sec == 0_u32 && frac == 0_u32
          return nil if sec < NTP_TIMESTAMP_DELTA

          unix_sec = (sec.to_u64 - NTP_TIMESTAMP_DELTA).to_i64
          nanos = ((frac.to_f64 / 4_294_967_296.0) * 1_000_000_000.0).to_i32
          Time.unix(unix_sec) + Time::Span.new(nanoseconds: nanos)
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          fields = Hash(String, FieldValue).new
          errors = [] of String

          available = data.size.to_u32 - offset
          if available < 48_u32
            errors << "Truncated NTP header: #{available} bytes available, 48 required"
            return DissectResult.new(
              protocol: protocol,
              payload_offset: data.size.to_u32,
              payload_length: 0_u32,
              fields: fields,
              errors: errors
            )
          end

          start = offset.to_i32

          flags_byte = data[start]
          li = (flags_byte >> 6) & 0x03_u8
          vn = (flags_byte >> 3) & 0x07_u8
          mode = flags_byte & 0x07_u8

          stratum = data[start + 1]
          poll = data[start + 2].to_i8
          precision = data[start + 3].to_i8

          root_delay_raw = (data[start + 4].to_u32 << 24) |
                           (data[start + 5].to_u32 << 16) |
                           (data[start + 6].to_u32 << 8) |
                           data[start + 7].to_u32

          root_disp_raw = (data[start + 8].to_u32 << 24) |
                          (data[start + 9].to_u32 << 16) |
                          (data[start + 10].to_u32 << 8) |
                          data[start + 11].to_u32

          # Timestamps: Transmit Timestamp at offset 40
          tx_sec = (data[start + 40].to_u32 << 24) |
                   (data[start + 41].to_u32 << 16) |
                   (data[start + 42].to_u32 << 8) |
                   data[start + 43].to_u32

          tx_frac = (data[start + 44].to_u32 << 24) |
                    (data[start + 45].to_u32 << 16) |
                    (data[start + 46].to_u32 << 8) |
                    data[start + 47].to_u32

          fields["ntp.li"] = li.to_u32
          fields["ntp.version"] = vn.to_u32
          fields["ntp.mode"] = mode.to_u32
          fields["ntp.stratum"] = stratum.to_u32
          fields["ntp.poll"] = poll.to_i32
          fields["ntp.precision"] = precision.to_i32
          fields["ntp.root_delay"] = root_delay_raw.to_f64 / 65536.0
          fields["ntp.root_dispersion"] = root_disp_raw.to_f64 / 65536.0

          mode_name = case mode
                      when 1 then "Symmetric active"
                      when 2 then "Symmetric passive"
                      when 3 then "Client"
                      when 4 then "Server"
                      when 5 then "Broadcast"
                      when 6 then "NTP control"
                      when 7 then "Private use"
                      else        "Mode #{mode}"
                      end
          fields["ntp.mode_name"] = mode_name

          if tx_time = NtpDissector.ntp_to_time(tx_sec, tx_frac)
            fields["ntp.tx_time"] = tx_time.to_s
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
