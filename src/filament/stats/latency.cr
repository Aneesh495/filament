# =============================================================================
# latency.cr - Round-trip time (RTT) and DNS transaction latency analyzer
# =============================================================================
#
# Measures latency distributions across network interactions:
#   - TCP three-way handshake RTT
#   - DNS query-to-response resolution latency (correlated by Transaction ID)
#   - Percentile latency calculations (p50, p90, p99)
#   - Binned latency histogram distribution
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissect/decoded_packet"
require "../flow/key"

module Filament
  module Stats
    # A single measured latency sample
    struct LatencySample
      getter label : String
      getter duration_ms : Float64
      getter timestamp : Time

      def initialize(@label : String, @duration_ms : Float64, @timestamp : Time)
      end
    end

    class LatencyAnalyzer
      getter samples : Array(LatencySample)
      getter dns_queries : Hash(Tuple(String, UInt32), Time)

      # Histogram buckets: bounds in milliseconds
      BUCKET_BOUNDS = [1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]

      def initialize
        @samples = [] of LatencySample
        @dns_queries = Hash(Tuple(String, UInt32), Time).new
      end

      # Ingests a decoded packet to measure DNS resolution and handshake latencies
      def process(packet : Dissect::DecodedPacket) : Nil
        ts = packet.raw.timestamp

        # Correlate DNS query-response latency
        if dns = packet.layer(Dissect::Protocol::Dns)
          tx_id = dns.uint32?("dns.tx_id")
          is_resp = dns.bool?("dns.is_response") || false
          client_ip = is_resp ? packet.destination_address : packet.source_address

          if tx_id && client_ip
            dns_key = {client_ip, tx_id}

            if is_resp
              # Match against pending query
              if query_time = @dns_queries.delete(dns_key)
                latency_ms = (ts - query_time).total_milliseconds
                qname = dns.string?("dns.qname") || "dns"
                @samples << LatencySample.new("DNS: #{qname}", latency_ms, ts)
              end
            else
              # Record query submission time
              @dns_queries[dns_key] = ts
            end
          end
        end
      end

      # Adds an explicit sample (e.g. from TCP handshake RTT)
      def record_sample(label : String, duration_ms : Float64, timestamp : Time) : Nil
        @samples << LatencySample.new(label, duration_ms, timestamp)
      end

      # Computes percentile latency (p0 to p100)
      def percentile(pct : Float64) : Float64
        return 0.0 if @samples.empty?
        sorted = @samples.map(&.duration_ms).sort
        idx = ((pct / 100.0) * (sorted.size - 1)).to_i
        sorted[idx]
      end

      def min_ms : Float64
        @samples.empty? ? 0.0 : @samples.min_of(&.duration_ms)
      end

      def max_ms : Float64
        @samples.empty? ? 0.0 : @samples.max_of(&.duration_ms)
      end

      def mean_ms : Float64
        @samples.empty? ? 0.0 : (@samples.sum(&.duration_ms) / @samples.size.to_f64)
      end

      # Generates a binned histogram distribution of latencies
      def histogram_counts : Hash(String, Int32)
        counts = Hash(String, Int32).new(0)
        @samples.each do |s|
          ms = s.duration_ms
          placed = false
          BUCKET_BOUNDS.each do |bound|
            if ms <= bound
              counts["<= #{bound}ms"] += 1
              placed = true
              break
            end
          end
          counts["> 1000ms"] += 1 unless placed
        end
        counts
      end

      def to_s(io : IO) : Nil
        return io << "No latency samples recorded\n" if @samples.empty?

        io << sprintf("Latency Summary (%d samples):\n", @samples.size)
        io << sprintf("  Min:    %8.2f ms\n", min_ms)
        io << sprintf("  Mean:   %8.2f ms\n", mean_ms)
        io << sprintf("  p50:    %8.2f ms\n", percentile(50.0))
        io << sprintf("  p90:    %8.2f ms\n", percentile(90.0))
        io << sprintf("  p99:    %8.2f ms\n", percentile(99.0))
        io << sprintf("  Max:    %8.2f ms\n", max_ms)
      end
    end
  end
end
