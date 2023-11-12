# =============================================================================
# table.cr - Bidirectional flow tracking table and timeout cache
# =============================================================================
#
# The FlowTable manages active conversations across the entire lifetime
# of a capture or streaming session. It correlates discrete packets into
# coherent bidirectional flows, updates counters and stream state, and
# evicts completed or inactive flows to bound memory consumption.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./record"

module Filament
  module Flow
    class FlowTable
      include Enumerable(FlowRecord)

      getter max_flows : Int32
      getter tcp_idle_timeout_sec : Float64
      getter udp_idle_timeout_sec : Float64
      getter tcp_closed_timeout_sec : Float64

      @table = Hash(FlowKey, FlowRecord).new

      def initialize(
        @max_flows : Int32 = 100_000,
        @tcp_idle_timeout_sec : Float64 = 300.0,
        @udp_idle_timeout_sec : Float64 = 60.0,
        @tcp_closed_timeout_sec : Float64 = 15.0
      )
      end

      # Ingests a decoded packet into the conversation table
      # Returns the associated FlowRecord (or nil if non-IP packet)
      def process(packet : Dissect::DecodedPacket) : FlowRecord?
        key = FlowKey.from_packet(packet)
        return nil unless key

        canonical_key, direction = key.canonical_with_direction
        ts = packet.raw.timestamp

        record = @table[canonical_key]?
        if record.nil?
          # Enforce capacity bound before creating new flow
          if @table.size >= @max_flows
            evict_oldest
          end

          record = FlowRecord.new(canonical_key, ts)
          @table[canonical_key] = record
        end

        record.update(packet, direction)
        record
      end

      # Retrieves flow record by exact or reverse key
      def find(key : FlowKey) : FlowRecord?
        @table[key.canonical]?
      end

      # Yields all currently tracked flow records
      def each(& : FlowRecord ->)
        @table.each_value do |rec|
          yield rec
        end
      end

      def size : Int32
        @table.size
      end

      # Returns top N flows sorted by total byte volume
      def top_by_bytes(n : Int32 = 10) : Array(FlowRecord)
        @table.values.sort_by { |f| -f.total_bytes.to_i64 }.first(n)
      end

      # Returns top N flows sorted by packet count
      def top_by_packets(n : Int32 = 10) : Array(FlowRecord)
        @table.values.sort_by { |f| -f.total_packets.to_i64 }.first(n)
      end

      # Evicts inactive or terminated flows relative to a reference time
      def expire_idle(now : Time) : Int32
        evicted = 0
        @table.reject! do |_key, record|
          idle = (now - record.last_seen).total_seconds
          timeout = if record.key.proto == 6_u8 # TCP
                      (record.fin_seen? || record.rst_seen?) ? @tcp_closed_timeout_sec : @tcp_idle_timeout_sec
                    else
                      @udp_idle_timeout_sec
                    end

          expired = idle > timeout
          evicted += 1 if expired
          expired
        end
        evicted
      end

      # Evicts the least recently seen flow when capacity is reached
      private def evict_oldest : Nil
        return if @table.empty?
        oldest_key = @table.min_by { |_k, v| v.last_seen }[0]
        @table.delete(oldest_key)
      end

      # Clears all entries from the flow table
      def clear : Nil
        @table.clear
      end
    end
  end
end
