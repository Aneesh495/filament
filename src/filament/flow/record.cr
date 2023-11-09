# =============================================================================
# record.cr - Bidirectional flow record and round-trip time (RTT) estimator
# =============================================================================
#
# Tracks accumulated state for an active network conversation:
#   - Forward and reverse packet/byte volumes
#   - First seen and last seen timestamps, duration, and bitrate
#   - Round-trip time (RTT) calculation from SYN / SYN-ACK delta and ACK echoes
#   - Identified application layer protocol and metadata (SNI, Host, URI)
#   - Associated unidirectional TCP stream reassemblers
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./key"
require "../dissect/layer4/tcp_stream"

module Filament
  module Flow
    class FlowRecord
      getter key : FlowKey
      getter start_time : Time
      getter last_seen : Time

      getter forward_packets : UInt64
      getter forward_bytes : UInt64
      getter reverse_packets : UInt64
      getter reverse_bytes : UInt64

      getter? syn_seen : Bool
      getter? syn_ack_seen : Bool
      getter? fin_seen : Bool
      getter? rst_seen : Bool

      # Estimated round-trip time in milliseconds
      getter rtt_ms : Float64?

      getter app_protocol : Dissect::Protocol?
      getter metadata : Hash(String, String)

      getter forward_assembler : Dissect::Layer4::TcpStreamReassembler
      getter reverse_assembler : Dissect::Layer4::TcpStreamReassembler

      @syn_time : Time?
      @syn_ack_time : Time?

      def initialize(@key : FlowKey, @start_time : Time)
        @last_seen = @start_time
        @forward_packets = 0_u64
        @forward_bytes = 0_u64
        @reverse_packets = 0_u64
        @reverse_bytes = 0_u64

        @syn_seen = false
        @syn_ack_seen = false
        @fin_seen = false
        @rst_seen = false

        @rtt_ms = nil
        @app_protocol = nil
        @metadata = Hash(String, String).new

        @forward_assembler = Dissect::Layer4::TcpStreamReassembler.new
        @reverse_assembler = Dissect::Layer4::TcpStreamReassembler.new
      end

      # Total packet volume across both directions
      def total_packets : UInt64
        @forward_packets + @reverse_packets
      end

      # Total byte volume across both directions
      def total_bytes : UInt64
        @forward_bytes + @reverse_bytes
      end

      # Flow lifetime duration in seconds
      def duration_seconds : Float64
        (@last_seen - @start_time).total_seconds
      end

      # Average data throughput in bytes per second
      def bytes_per_second : Float64
        dur = duration_seconds
        dur > 0.0001 ? (total_bytes.to_f64 / dur) : total_bytes.to_f64
      end

      # Updates record with newly observed packet
      def update(packet : Dissect::DecodedPacket, direction : FlowDirection) : Nil
        ts = packet.raw.timestamp
        @last_seen = ts if ts > @last_seen

        bytes = packet.raw.captured_length.to_u64
        if direction == FlowDirection::Forward
          @forward_packets += 1_u64
          @forward_bytes += bytes
        else
          @reverse_packets += 1_u64
          @reverse_bytes += bytes
        end

        # Track TCP flags and RTT handshake timestamps
        if tcp = packet.layer(Dissect::Protocol::Tcp)
          syn = tcp.bool?("tcp.flags.syn") || false
          ack = tcp.bool?("tcp.flags.ack") || false
          fin = tcp.bool?("tcp.flags.fin") || false
          rst = tcp.bool?("tcp.flags.rst") || false

          @fin_seen = true if fin
          @rst_seen = true if rst

          if syn && !ack
            @syn_seen = true
            @syn_time = ts
          elsif syn && ack
            @syn_ack_seen = true
            @syn_ack_time = ts
            if s_time = @syn_time
              # Initial RTT estimation from SYN -> SYN-ACK delta
              @rtt_ms = (ts - s_time).total_milliseconds
            end
          end
        end

        # Record higher layer protocol identification
        top = packet.highest_protocol
        if top.application_layer?
          @app_protocol = top
          record_app_metadata(packet, top)
        end
      end

      # Extracts high-value protocol metadata strings
      private def record_app_metadata(packet : Dissect::DecodedPacket, proto : Dissect::Protocol) : Nil
        case proto
        when Dissect::Protocol::Dns
          if q = packet.field("dns.qname")
            @metadata["dns.query"] = q.to_s
          end
        when Dissect::Protocol::Http
          if m = packet.field("http.method")
            @metadata["http.method"] = m.to_s
          end
          if u = packet.field("http.uri")
            @metadata["http.uri"] = u.to_s
          end
          if h = packet.field("http.host")
            @metadata["http.host"] = h.to_s
          end
        when Dissect::Protocol::Tls
          if sni = packet.field("tls.sni")
            @metadata["tls.sni"] = sni.to_s
          end
        end
      end
    end
  end
end
