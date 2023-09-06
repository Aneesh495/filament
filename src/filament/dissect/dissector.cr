# =============================================================================
# dissector.cr - Extensible protocol dissection framework
# =============================================================================
#
# Dissection in filament follows a layered pipeline architecture inspired by
# Wireshark/Ethereal's packet dissector tree, but designed for zero unnecessary
# allocations and high-speed traversal in Crystal.
#
# Each layer parses its own header, extracts typed key-value fields into a
# DissectResult record, computes the byte offset and length where the next
# protocol begins, and optionally hints what next protocol to invoke based
# on demultiplexing fields (such as EtherType, IP protocol number, or TCP/UDP
# destination port).
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../capture/packet"

module Filament
  module Dissect
    # Recognized protocol identifiers across all OSI model layers
    enum Protocol
      Unknown
      Ethernet
      Vlan
      Arp
      Sll
      Ppp
      IPv4
      IPv6
      Icmp
      Icmpv6
      Tcp
      Udp
      Dns
      Http
      Tls
      Dhcp
      Ntp
      Smtp
      WebSocket

      # Returns true if protocol belongs to Link Layer (L2)
      def link_layer? : Bool
        self.in?(Ethernet, Vlan, Arp, Sll, Ppp)
      end

      # Returns true if protocol belongs to Network / Internet Layer (L3)
      def network_layer? : Bool
        self.in?(IPv4, IPv6, Icmp, Icmpv6)
      end

      # Returns true if protocol belongs to Transport Layer (L4)
      def transport_layer? : Bool
        self.in?(Tcp, Udp)
      end

      # Returns true if protocol belongs to Application Layer (L7)
      def application_layer? : Bool
        self.in?(Dns, Http, Tls, Dhcp, Ntp, Smtp, WebSocket)
      end
    end

    # Heterogeneous value type for protocol header and payload fields
    alias FieldValue = Nil | Bool | UInt8 | UInt16 | UInt32 | UInt64 | Int32 | Int64 | Float64 | String | Bytes | Array(FieldValue) | Hash(String, FieldValue)

    # Dissection outcome for a single protocol layer within a packet
    struct DissectResult
      getter protocol : Protocol
      getter fields : Hash(String, FieldValue)
      getter payload_offset : UInt32
      getter payload_length : UInt32
      getter next_protocol : Protocol?
      getter errors : Array(String)

      def initialize(
        @protocol : Protocol,
        @payload_offset : UInt32,
        @payload_length : UInt32,
        @fields : Hash(String, FieldValue) = Hash(String, FieldValue).new,
        @next_protocol : Protocol? = nil,
        @errors : Array(String) = [] of String
      )
      end

      # Convenience field lookup
      def [](key : String) : FieldValue
        @fields[key]
      end

      def []?(key : String) : FieldValue?
        @fields[key]?
      end

      def string?(key : String) : String?
        val = @fields[key]?
        val.is_a?(String) ? val : nil
      end

      def uint32?(key : String) : UInt32?
        val = @fields[key]?
        case val
        when UInt32 then val
        when UInt16 then val.to_u32
        when UInt8  then val.to_u32
        when Int32  then val.to_u32
        else nil
        end
      end

      def uint16?(key : String) : UInt16?
        val = @fields[key]?
        case val
        when UInt16 then val
        when UInt8  then val.to_u16
        else nil
        end
      end

      def bool?(key : String) : Bool?
        val = @fields[key]?
        val.is_a?(Bool) ? val : nil
      end

      def bytes?(key : String) : Bytes?
        val = @fields[key]?
        val.is_a?(Bytes) ? val : nil
      end

      def valid? : Bool
        @errors.empty?
      end
    end

    # Abstract base class for all protocol dissectors
    abstract class Dissector
      abstract def protocol : Protocol
      abstract def name : String
      abstract def dissect(data : Bytes, offset : UInt32) : DissectResult

      # Fast predicate to check if the buffer at offset appears to match this protocol
      def can_dissect?(data : Bytes, offset : UInt32) : Bool
        offset < data.size
      end
    end

    # Central registry coordinating layered protocol dissection
    class DissectorRegistry
      # Singleton instance
      @@instance : DissectorRegistry = new

      def self.instance : DissectorRegistry
        @@instance
      end

      @dissectors = Hash(Protocol, Dissector).new
      @port_map_tcp = Hash(UInt16, Protocol).new
      @port_map_udp = Hash(UInt16, Protocol).new

      def initialize
        # Configure standard well-known port mappings for L7 inference
        @port_map_tcp[80_u16] = Protocol::Http
        @port_map_tcp[8080_u16] = Protocol::Http
        @port_map_tcp[443_u16] = Protocol::Tls
        @port_map_tcp[8443_u16] = Protocol::Tls
        @port_map_tcp[25_u16] = Protocol::Smtp
        @port_map_tcp[587_u16] = Protocol::Smtp
        @port_map_tcp[53_u16] = Protocol::Dns

        @port_map_udp[53_u16] = Protocol::Dns
        @port_map_udp[67_u16] = Protocol::Dhcp
        @port_map_udp[68_u16] = Protocol::Dhcp
        @port_map_udp[123_u16] = Protocol::Ntp
      end

      # Registers a dissector instance
      def register(dissector : Dissector) : Nil
        @dissectors[dissector.protocol] = dissector
      end

      # Retrieves dissector for given protocol
      def get(protocol : Protocol) : Dissector?
        @dissectors[protocol]?
      end

      # Suggests L7 protocol based on transport port numbers
      def infer_l7_protocol(transport_proto : Protocol, src_port : UInt16, dst_port : UInt16) : Protocol?
        map = (transport_proto == Protocol::Tcp) ? @port_map_tcp : @port_map_udp
        map[dst_port]? || map[src_port]?
      end

      # Walks the entire protocol stack for a raw packet, returning all decoded layers
      def dissect_chain(packet : Filament::Capture::RawPacket) : Array(DissectResult)
        layers = [] of DissectResult
        data = packet.data
        return layers if data.empty?

        # Determine initial layer 2 protocol from capture link type
        current_proto : Protocol? = case packet.link_type
                                    when Filament::Capture::LinkType::Ethernet
                                      Protocol::Ethernet
                                    when Filament::Capture::LinkType::LinuxSll, Filament::Capture::LinkType::LinuxSll2
                                      Protocol::Sll
                                    when Filament::Capture::LinkType::Raw
                                      # Infer IPv4 or IPv6 from initial nibble
                                      first_byte = data[0]?
                                      if first_byte
                                        version = first_byte >> 4
                                        version == 6 ? Protocol::IPv6 : Protocol::IPv4
                                      else
                                        nil
                                      end
                                    else
                                      Protocol::Ethernet
                                    end

        current_offset = 0_u32

        while current_proto && current_offset < data.size
          dissector = @dissectors[current_proto]?
          break unless dissector

          result = dissector.dissect(data, current_offset)
          layers << result

          # Check if dissection indicated a follow-up protocol
          next_proto = result.next_protocol

          # If next protocol was not explicitly deduced, attempt L7 inference if at L4
          if next_proto.nil? && result.protocol.in?(Protocol::Tcp, Protocol::Udp)
            src_p = result.uint16?("#{result.protocol.to_s.downcase}.src_port")
            dst_p = result.uint16?("#{result.protocol.to_s.downcase}.dst_port")
            if src_p && dst_p
              next_proto = infer_l7_protocol(result.protocol, src_p, dst_p)
            end
          end

          break if result.payload_length == 0_u32 || next_proto.nil?

          current_offset = result.payload_offset
          current_proto = next_proto
        end

        layers
      end
    end
  end
end
