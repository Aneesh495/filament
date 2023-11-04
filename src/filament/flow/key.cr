# =============================================================================
# key.cr - 5-tuple network flow key and canonical conversation indexing
# =============================================================================
#
# A network flow represents a sequence of packets exchanged between two
# communication endpoints sharing the standard 5-tuple:
#   (Source IP, Destination IP, Source Port, Destination Port, Protocol)
#
# Because network conversations are inherently bidirectional (client to server
# and server to client), Filament computes canonical keys where the lower
# endpoint tuple always orders first. This guarantees that both forward and
# reverse directions map into the exact same FlowRecord in the global flow table,
# while preserving per-direction packet and byte counters.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector/dissector"

module Filament
  module Flow
    enum FlowDirection
      Forward
      Reverse
    end

    # Direction-specific 5-tuple key
    struct FlowKey
      getter src_ip : String
      getter dst_ip : String
      getter src_port : UInt16
      getter dst_port : UInt16
      getter proto : UInt8

      def initialize(
        @src_ip : String,
        @dst_ip : String,
        @src_port : UInt16,
        @dst_port : UInt16,
        @proto : UInt8
      )
      end

      # Derives flow key from a decoded packet
      def self.from_packet(packet : Dissect::DecodedPacket) : FlowKey?
        src = packet.source_address
        dst = packet.destination_address
        return nil unless src && dst

        sp = packet.source_port || 0_u16
        dp = packet.destination_port || 0_u16

        # Determine L4 protocol byte
        proto_num = if packet.has_protocol?(Dissect::Protocol::Tcp)
                      6_u8
                    elsif packet.has_protocol?(Dissect::Protocol::Udp)
                      17_u8
                    elsif packet.has_protocol?(Dissect::Protocol::Icmp)
                      1_u8
                    elsif packet.has_protocol?(Dissect::Protocol::Icmpv6)
                      58_u8
                    else
                      0_u8
                    end

        new(src, dst, sp, dp, proto_num)
      end

      # Returns the reversed flow key (swapped endpoints)
      def reverse : FlowKey
        FlowKey.new(@dst_ip, @src_ip, @dst_port, @src_port, @proto)
      end

      # Returns canonical representation and direction (:forward or :reverse)
      def canonical_with_direction : Tuple(FlowKey, FlowDirection)
        # Lexicographical comparison of (ip, port) pairs
        forward_is_first = if @src_ip != @dst_ip
                             @src_ip < @dst_ip
                           else
                             @src_port <= @dst_port
                           end

        if forward_is_first
          {self, FlowDirection::Forward}
        else
          {reverse, FlowDirection::Reverse}
        end
      end

      def canonical : FlowKey
        canonical_with_direction[0]
      end

      def_hash @src_ip, @dst_ip, @src_port, @dst_port, @proto
      def_equals @src_ip, @dst_ip, @src_port, @dst_port, @proto

      def to_s(io : IO) : Nil
        proto_name = case @proto
                     when 6  then "TCP"
                     when 17 then "UDP"
                     when 1  then "ICMP"
                     when 58 then "ICMPv6"
                     else "IP(#{@proto})"
                     end
        io << @src_ip << ":" << @src_port << " -> " << @dst_ip << ":" << @dst_port << " [" << proto_name << "]"
      end
    end
  end
end
