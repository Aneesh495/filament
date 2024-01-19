# =============================================================================
# format.cr - String formatting, human unit conversion, and table printers
# =============================================================================
#
# Provides human-friendly formatting helpers for packet numbers, byte counts,
# transfer bitrates, relative timestamps, and columnar terminal tables.
#
# Author: filament contributors
# License: MIT
# =============================================================================

module Filament
  module Util
    module Format
      # Formats byte counts into human readable decimal units (KB, MB, GB)
      def self.human_bytes(bytes : UInt64 | Int64 | Float64) : String
        b = bytes.to_f64
        if b < 1024.0
          sprintf("%d B", b.to_i64)
        elsif b < 1024.0 * 1024.0
          sprintf("%.2f KB", b / 1024.0)
        elsif b < 1024.0 * 1024.0 * 1024.0
          sprintf("%.2f MB", b / (1024.0 * 1024.0))
        else
          sprintf("%.2f GB", b / (1024.0 * 1024.0 * 1024.0))
        end
      end

      # Formats bitrates into bps, kbps, mbps, gbps
      def self.human_bits_per_sec(bps : Float64) : String
        if bps < 1000.0
          sprintf("%.1f bps", bps)
        elsif bps < 1_000_000.0
          sprintf("%.2f kbps", bps / 1000.0)
        elsif bps < 1_000_000_000.0
          sprintf("%.2f mbps", bps / 1_000_000.0)
        else
          sprintf("%.2f gbps", bps / 1_000_000_000.0)
        end
      end

      # Formats relative duration in seconds with microsecond resolution
      def self.relative_time(delta : Time::Span) : String
        secs = delta.total_seconds
        sprintf("%8.6f", secs)
      end
    end
  end
end
