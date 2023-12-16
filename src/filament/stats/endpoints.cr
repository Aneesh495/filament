# =============================================================================
# endpoints.cr - Endpoint volume statistics table
# =============================================================================
#
# Aggregates network traffic metrics by individual physical (MAC) and logical
# (IPv4, IPv6) endpoint addresses, computing transmitted and received packet
# counts and byte volumes.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissect/decoded_packet"

module Filament
  module Stats
    class EndpointStats
      getter address : String
      getter tx_packets : UInt64
      getter tx_bytes : UInt64
      getter rx_packets : UInt64
      getter rx_bytes : UInt64

      def initialize(@address : String)
        @tx_packets = 0_u64
        @tx_bytes = 0_u64
        @rx_packets = 0_u64
        @rx_bytes = 0_u64
      end

      def total_packets : UInt64
        @tx_packets + @rx_packets
      end

      def total_bytes : UInt64
        @tx_bytes + @rx_bytes
      end

      def record_tx(bytes : UInt64) : Nil
        @tx_packets += 1_u64
        @tx_bytes += bytes
      end

      def record_rx(bytes : UInt64) : Nil
        @rx_packets += 1_u64
        @rx_bytes += bytes
      end
    end

    class EndpointsTable
      getter endpoints : Hash(String, EndpointStats)

      def initialize
        @endpoints = Hash(String, EndpointStats).new
      end

      # Updates endpoint statistics for an incoming decoded packet
      def process(packet : Dissect::DecodedPacket) : Nil
        src = packet.source_address
        dst = packet.destination_address
        bytes = packet.raw.captured_length.to_u64

        if src
          entry = @endpoints.put_if_absent(src) { EndpointStats.new(src) }
          entry.record_tx(bytes)
        end

        if dst
          entry = @endpoints.put_if_absent(dst) { EndpointStats.new(dst) }
          entry.record_rx(bytes)
        end
      end

      # Returns top N endpoints sorted by total byte volume
      def top_by_bytes(n : Int32 = 10) : Array(EndpointStats)
        @endpoints.values.sort_by { |e| -e.total_bytes.to_i64 }.first(n)
      end

      # Formats tabular representation of endpoints
      def to_s(io : IO) : Nil
        io << sprintf("%-30s %10s %12s %10s %12s %12s\n", "Endpoint Address", "Tx Pkts", "Tx Bytes", "Rx Pkts", "Rx Bytes", "Total Bytes")
        io << "-" * 90 << "\n"

        top_by_bytes(25).each do |ep|
          io << sprintf("%-30s %10d %12d %10d %12d %12d\n",
            ep.address,
            ep.tx_packets,
            ep.tx_bytes,
            ep.rx_packets,
            ep.rx_bytes,
            ep.total_bytes
          )
        end
      end
    end
  end
end
