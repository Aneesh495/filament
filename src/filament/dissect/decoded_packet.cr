# =============================================================================
# decoded_packet.cr - High-level decoded packet model and hex dump utility
# =============================================================================
#
# Represents a fully dissected network packet with all recognized protocol
# layers, extracted typed fields, calculated summary information, and
# ergonomic query methods.
#
# Also includes a high-speed hex dump formatting utility with ASCII sidebar
# rendering for packet inspections.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../capture/packet"
require "./dissector"

module Filament
  module Dissect
    # Fully dissected packet containing raw bytes and decoded layer results
    class DecodedPacket
      getter raw : Filament::Capture::RawPacket
      getter layers : Array(DissectResult)
      getter packet_id : UInt64

      def initialize(@raw : Filament::Capture::RawPacket, @layers : Array(DissectResult), @packet_id : UInt64 = 0_u64)
      end

      # Convenience constructor decoding raw packet through global registry
      def self.decode(packet : Filament::Capture::RawPacket, id : UInt64 = 0_u64) : DecodedPacket
        layers = DissectorRegistry.instance.dissect_chain(packet)
        new(packet, layers, id)
      end

      # Checks if packet contains a specific protocol layer
      def has_protocol?(proto : Protocol) : Bool
        @layers.any? { |l| l.protocol == proto }
      end

      # Retrieves dissection result for specific protocol
      def layer(proto : Protocol) : DissectResult?
        @layers.find { |l| l.protocol == proto }
      end

      # Queries field across layers using dotted path (e.g. "ip.src", "tcp.dst_port")
      def field(path : String) : FieldValue?
        parts = path.split(".", 2)
        return nil if parts.size < 2

        prefix = parts[0].downcase
        # Find matching layer
        target_layer = @layers.find do |l|
          proto_name = l.protocol.to_s.downcase
          proto_name == prefix || (proto_name == "ipv4" && prefix == "ip")
        end

        return nil unless target_layer
        target_layer.fields[path]?
      end

      # Queries field directly with explicit protocol and field name
      def field(proto : Protocol, name : String) : FieldValue?
        lyr = layer(proto)
        lyr ? lyr.fields[name]? : nil
      end

      # Returns highest (topmost) recognized OSI protocol in the stack
      def highest_protocol : Protocol
        @layers.last?.try(&.protocol) || Protocol::Unknown
      end

      # Source address resolved from network layer (IPv4/IPv6) or link layer (Ethernet)
      def source_address : String?
        if ip4 = layer(Protocol::IPv4)
          ip4.string?("ip.src")
        elsif ip6 = layer(Protocol::IPv6)
          ip6.string?("ipv6.src")
        elsif eth = layer(Protocol::Ethernet)
          eth.string?("eth.src")
        elsif arp = layer(Protocol::Arp)
          arp.string?("arp.src_ip")
        else
          nil
        end
      end

      # Destination address resolved from network or link layer
      def destination_address : String?
        if ip4 = layer(Protocol::IPv4)
          ip4.string?("ip.dst")
        elsif ip6 = layer(Protocol::IPv6)
          ip6.string?("ipv6.dst")
        elsif eth = layer(Protocol::Ethernet)
          eth.string?("eth.dst")
        elsif arp = layer(Protocol::Arp)
          arp.string?("arp.dst_ip")
        else
          nil
        end
      end

      # Source transport port (TCP/UDP)
      def source_port : UInt16?
        if tcp = layer(Protocol::Tcp)
          tcp.uint16?("tcp.src_port")
        elsif udp = layer(Protocol::Udp)
          udp.uint16?("udp.src_port")
        else
          nil
        end
      end

      # Destination transport port (TCP/UDP)
      def destination_port : UInt16?
        if tcp = layer(Protocol::Tcp)
          tcp.uint16?("tcp.dst_port")
        elsif udp = layer(Protocol::Udp)
          udp.uint16?("udp.dst_port")
        else
          nil
        end
      end

      # Formats a concise one-line summary string for packet listings
      def summary : String
        src = source_address || "?"
        dst = destination_address || "?"

        sp = source_port
        dp = destination_port

        endpoints = if sp && dp
                      "#{src}:#{sp} -> #{dst}:#{dp}"
                    else
                      "#{src} -> #{dst}"
                    end

        top = highest_protocol.to_s.upcase
        details = layer_summary(highest_protocol)

        sprintf("#%-5d %-28s %-8s %s", @packet_id, endpoints, top, details)
      end

      # Contextual details for highest layer
      private def layer_summary(proto : Protocol) : String
        lyr = layer(proto)
        return "" unless lyr

        case proto
        when Protocol::Dns
          qname = lyr.string?("dns.qname") || ""
          qtype = lyr.string?("dns.qtype") || ""
          is_resp = lyr.bool?("dns.is_response") || false
          is_resp ? "Response #{qname}" : "Standard query #{qtype} #{qname}"
        when Protocol::Http
          if m = lyr.string?("http.method")
            uri = lyr.string?("http.uri") || "/"
            "#{m} #{uri}"
          elsif s = lyr.uint16?("http.status_code")
            phrase = lyr.string?("http.reason") || ""
            "HTTP #{s} #{phrase}"
          else
            "HTTP payload"
          end
        when Protocol::Tls
          ver = lyr.string?("tls.version") || ""
          type_str = lyr.string?("tls.type") || ""
          "#{ver} #{type_str}"
        when Protocol::Tcp
          flags = lyr.string?("tcp.flags_str") || ""
          seq = lyr.uint32?("tcp.seq") || 0_u32
          ack = lyr.uint32?("tcp.ack") || 0_u32
          win = lyr.uint16?("tcp.window_size") || 0_u16
          "[#{flags}] Seq=#{seq} Ack=#{ack} Win=#{win}"
        when Protocol::Udp
          len = lyr.uint16?("udp.length") || 0_u16
          "Len=#{len}"
        when Protocol::Icmp
          type_name = lyr.string?("icmp.type_name") || ""
          type_name
        when Protocol::Arp
          op = lyr.string?("arp.operation_name") || ""
          "#{op}"
        else
          "Len=#{@raw.captured_length}"
        end
      end

      # Produces formatted hex + ASCII dump
      def hex_dump(offset : Int32 = 0, length : Int32? = nil) : String
        bytes = @raw.data
        start_idx = Math.min(offset, bytes.size)
        max_len = bytes.size - start_idx
        len = length ? Math.min(length, max_len) : max_len

        String.build do |io|
          slice = bytes[start_idx, len]
          row_count = (slice.size + 15) // 16

          row_count.times do |row|
            row_offset = row * 16
            # Offset column: 00000000
            io << sprintf("%08x  ", start_idx + row_offset)

            # Hex bytes: 16 bytes separated with a space between 8-byte blocks
            16.times do |col|
              idx = row_offset + col
              if idx < slice.size
                io << sprintf("%02x ", slice[idx])
              else
                io << "   "
              end
              io << " " if col == 7
            end

            io << " |"

            # ASCII sidebar
            16.times do |col|
              idx = row_offset + col
              if idx < slice.size
                byte = slice[idx]
                if byte >= 32 && byte <= 126
                  io << byte.unsafe_chr
                else
                  io << '.'
                end
              end
            end

            io << "|\n"
          end
        end
      end
    end
  end
end
