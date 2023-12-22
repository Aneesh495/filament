# =============================================================================
# io_rate.cr - Time-bucketed I/O throughput and packet rate analyzer
# =============================================================================
#
# Partitions captured packet streams into discrete chronological time buckets
# (e.g. 1-second or 100-millisecond intervals) to compute instantaneous and
# average transfer rates, burst dynamics, and terminal ASCII rate graphs.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissect/decoded_packet"

module Filament
  module Stats
    struct TimeBucket
      getter start_time : Time
      getter packet_count : UInt64
      getter byte_count : UInt64

      def initialize(@start_time : Time, @packet_count : UInt64 = 0_u64, @byte_count : UInt64 = 0_u64)
      end

      def with_packet(bytes : UInt64) : TimeBucket
        TimeBucket.new(@start_time, @packet_count + 1_u64, @byte_count + bytes)
      end

      # Throughput in bits per second over a 1-second interval
      def bits_per_second : Float64
        @byte_count.to_f64 * 8.0
      end
    end

    class IoRateAnalyzer
      getter bucket_duration : Time::Span
      getter buckets : Hash(Int64, TimeBucket)
      getter base_time : Time?

      def initialize(@bucket_duration : Time::Span = Time::Span.new(seconds: 1))
        @buckets = Hash(Int64, TimeBucket).new
        @base_time = nil
      end

      # Ingests a decoded packet into the appropriate chronological bucket
      def process(packet : Dissect::DecodedPacket) : Nil
        ts = packet.raw.timestamp
        bytes = packet.raw.captured_length.to_u64

        if @base_time.nil?
          @base_time = ts
        end

        base = @base_time.not_nil!
        bucket_index = ((ts - base).total_seconds / @bucket_duration.total_seconds).to_i64

        cur = @buckets[bucket_index]?
        if cur.nil?
          bucket_start = base + (@bucket_duration * bucket_index)
          @buckets[bucket_index] = TimeBucket.new(bucket_start, 1_u64, bytes)
        else
          @buckets[bucket_index] = cur.with_packet(bytes)
        end
      end

      # Peak byte volume observed in any single bucket
      def peak_bytes_per_bucket : UInt64
        return 0_u64 if @buckets.empty?
        @buckets.values.max_of(&.byte_count)
      end

      # Peak packet volume observed in any single bucket
      def peak_packets_per_bucket : UInt64
        return 0_u64 if @buckets.empty?
        @buckets.values.max_of(&.packet_count)
      end

      # Generates a text ASCII sparkline graph representing throughput over time
      def ascii_chart(width : Int32 = 60) : String
        return "No traffic recorded" if @buckets.empty?

        sorted_keys = @buckets.keys.sort
        min_k = sorted_keys.first
        max_k = sorted_keys.last

        peak = peak_bytes_per_bucket
        return "Zero bytes recorded" if peak == 0_u64

        chars = [' ', '.', ':', '-', '=', '+', '*', '#', '%', '@']

        String.build do |io|
          io << "Time-bucket throughput graph (Bucket = " << @bucket_duration << "):\n"
          io << "Peak: " << (peak * 8 // 1000) << " kbps\n["

          (min_k..max_k).each do |k|
            b = @buckets[k]?
            bytes = b ? b.byte_count : 0_u64
            ratio = bytes.to_f64 / peak.to_f64
            char_idx = Math.min((ratio * (chars.size - 1)).to_i, chars.size - 1)
            io << chars[char_idx]
          end

          io << "]\n"
        end
      end
    end
  end
end
