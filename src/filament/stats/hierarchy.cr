# =============================================================================
# hierarchy.cr - Protocol hierarchy tree aggregator and statistics
# =============================================================================
#
# Generates a hierarchical breakdown of network protocols observed in a packet
# capture, tracking packet counts, byte volumes, and percentage contributions
# at each level of the OSI protocol stack.
#
# Example visual output:
#   Protocol               Packets     Percent     Bytes       Percent
#   ------------------------------------------------------------------
#   Ethernet               10,000      100.0%      8.42 MB     100.0%
#     IPv4                  9,850       98.5%      8.31 MB      98.7%
#       TCP                 8,200       82.0%      7.50 MB      89.1%
#         HTTP              4,100       41.0%      3.80 MB      45.1%
#         TLS               3,800       38.0%      3.55 MB      42.2%
#       UDP                 1,650       16.5%      810.0 KB      9.6%
#         DNS               1,650       16.5%      810.0 KB      9.6%
#     ARP                     150        1.5%       9.00 KB      0.1%
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissect/decoded_packet"

module Filament
  module Stats
    class ProtocolNode
      getter protocol : Dissect::Protocol
      getter packet_count : UInt64
      getter byte_count : UInt64
      getter children : Hash(Dissect::Protocol, ProtocolNode)

      def initialize(@protocol : Dissect::Protocol)
        @packet_count = 0_u64
        @byte_count = 0_u64
        @children = Hash(Dissect::Protocol, ProtocolNode).new
      end

      def record_packet(bytes : UInt64) : Nil
        @packet_count += 1_u64
        @byte_count += bytes
      end

      def get_or_create_child(proto : Dissect::Protocol) : ProtocolNode
        @children.put_if_absent(proto) { ProtocolNode.new(proto) }
      end
    end

    class ProtocolHierarchy
      getter root_nodes : Hash(Dissect::Protocol, ProtocolNode)
      getter total_packets : UInt64
      getter total_bytes : UInt64

      def initialize
        @root_nodes = Hash(Dissect::Protocol, ProtocolNode).new
        @total_packets = 0_u64
        @total_bytes = 0_u64
      end

      # Ingests a decoded packet into the protocol tree
      def process(packet : Dissect::DecodedPacket) : Nil
        layers = packet.layers
        return if layers.empty?

        bytes = packet.raw.captured_length.to_u64
        @total_packets += 1_u64
        @total_bytes += bytes

        first_proto = layers[0].protocol
        current_node = @root_nodes.put_if_absent(first_proto) { ProtocolNode.new(first_proto) }
        current_node.record_packet(bytes)

        (1...layers.size).each do |i|
          layer_proto = layers[i].protocol
          current_node = current_node.get_or_create_child(layer_proto)
          current_node.record_packet(bytes)
        end
      end

      # Formats hierarchy into a tabular text tree
      def to_s(io : IO) : Nil
        io << sprintf("%-30s %10s %10s %12s %10s\n", "Protocol", "Packets", "% Packets", "Bytes", "% Bytes")
        io << "-" * 76 << "\n"

        @root_nodes.each_value do |root|
          render_node(io, root, 0)
        end
      end

      private def render_node(io : IO, node : ProtocolNode, depth : Int32) : Nil
        indent = "  " * depth
        name_str = "#{indent}#{node.protocol}"

        pkt_pct = @total_packets > 0 ? (node.packet_count.to_f64 / @total_packets.to_f64 * 100.0) : 0.0
        byte_pct = @total_bytes > 0 ? (node.byte_count.to_f64 / @total_bytes.to_f64 * 100.0) : 0.0

        io << sprintf("%-30s %10d %9.1f%% %12d %9.1f%%\n",
          name_str,
          node.packet_count,
          pkt_pct,
          node.byte_count,
          byte_pct
        )

        node.children.each_value do |child|
          render_node(io, child, depth + 1)
        end
      end
    end
  end
end
