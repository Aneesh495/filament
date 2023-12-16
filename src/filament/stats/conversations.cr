# =============================================================================
# conversations.cr - Conversation pair matrix and statistical summary
# =============================================================================
#
# Aggregates bidirectional traffic flows between pairs of network hosts,
# providing summary matrices by Layer 2 (MAC), Layer 3 (IPv4/IPv6), and
# Layer 4 (TCP/UDP) conversation endpoints.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissect/decoded_packet"
require "../flow/key"

module Filament
  module Stats
    class ConversationStats
      getter endpoint_a : String
      getter endpoint_b : String
      getter packets_a_to_b : UInt64
      getter bytes_a_to_b : UInt64
      getter packets_b_to_a : UInt64
      getter bytes_b_to_a : UInt64
      getter start_time : Time
      getter last_seen : Time

      def initialize(@endpoint_a : String, @endpoint_b : String, @start_time : Time)
        @last_seen = @start_time
        @packets_a_to_b = 0_u64
        @bytes_a_to_b = 0_u64
        @packets_b_to_a = 0_u64
        @bytes_b_to_a = 0_u64
      end

      def total_packets : UInt64
        @packets_a_to_b + @packets_b_to_a
      end

      def total_bytes : UInt64
        @bytes_a_to_b + @bytes_b_to_a
      end

      def duration_seconds : Float64
        (@last_seen - @start_time).total_seconds
      end

      def record_transfer(from_a : Bool, bytes : UInt64, ts : Time) : Nil
        @last_seen = ts if ts > @last_seen
        if from_a
          @packets_a_to_b += 1_u64
          @bytes_a_to_b += bytes
        else
          @packets_b_to_a += 1_u64
          @bytes_b_to_a += bytes
        end
      end
    end

    class ConversationsTable
      getter conversations : Hash(Tuple(String, String), ConversationStats)

      def initialize
        @conversations = Hash(Tuple(String, String), ConversationStats).new
      end

      # Updates conversation stats for an incoming packet
      def process(packet : Dissect::DecodedPacket) : Nil
        src = packet.source_address
        dst = packet.destination_address
        return unless src && dst

        ts = packet.raw.timestamp
        bytes = packet.raw.captured_length.to_u64

        # Canonical ordering so A <= B
        if src <= dst
          pair = {src, dst}
          entry = @conversations.put_if_absent(pair) { ConversationStats.new(src, dst, ts) }
          entry.record_transfer(from_a: true, bytes: bytes, ts: ts)
        else
          pair = {dst, src}
          entry = @conversations.put_if_absent(pair) { ConversationStats.new(dst, src, ts) }
          entry.record_transfer(from_a: false, bytes: bytes, ts: ts)
        end
      end

      def top_by_bytes(n : Int32 = 10) : Array(ConversationStats)
        @conversations.values.sort_by { |c| -c.total_bytes.to_i64 }.first(n)
      end

      def to_s(io : IO) : Nil
        io << sprintf("%-24s <-> %-24s %8s %10s %8s %10s %10s\n",
          "Address A", "Address B", "Pkts A->B", "Bytes A->B", "Pkts B->A", "Bytes B->A", "Total Bytes")
        io << "-" * 102 << "\n"

        top_by_bytes(25).each do |c|
          io << sprintf("%-24s <-> %-24s %8d %10d %8d %10d %10d\n",
            c.endpoint_a,
            c.endpoint_b,
            c.packets_a_to_b,
            c.bytes_a_to_b,
            c.packets_b_to_a,
            c.bytes_b_to_a,
            c.total_bytes
          )
        end
      end
    end
  end
end
