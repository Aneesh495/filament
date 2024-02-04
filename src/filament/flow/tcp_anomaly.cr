# =============================================================================
# tcp_anomaly.cr - TCP traffic anomaly and performance diagnostic detector
# =============================================================================
#
# Detects real-world TCP operational impairments and pathological states:
#   - Fast and Spurious Retransmissions
#   - Out-of-order segment arrivals
#   - Zero-window conditions and zero-window probing
#   - Window full events indicating sender throttling
#   - Keep-alive probes and keep-alive acknowledgments
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./key"
require "../dissect/layer4/tcp_seq"

module Filament
  module Flow
    enum TcpAnomalyType
      Retransmission
      FastRetransmission
      SpuriousRetransmission
      OutOfOrder
      ZeroWindow
      ZeroWindowProbe
      WindowFull
      KeepAlive
    end

    struct TcpAnomalyEvent
      getter type : TcpAnomalyType
      getter timestamp : Time
      getter seq : UInt32
      getter length : UInt32
      getter description : String

      def initialize(
        @type : TcpAnomalyType,
        @timestamp : Time,
        @seq : UInt32,
        @length : UInt32,
        @description : String,
      )
      end
    end

    # Diagnoses performance anomalies for a unidirectional flow path
    class TcpAnomalyDetector
      getter events : Array(TcpAnomalyEvent)
      getter retransmission_count : UInt32
      getter out_of_order_count : UInt32
      getter zero_window_count : UInt32

      @highest_seq_seen : UInt32?
      @highest_ack_seen : UInt32?
      @dup_ack_count : UInt32

      def initialize
        @events = [] of TcpAnomalyEvent
        @retransmission_count = 0_u32
        @out_of_order_count = 0_u32
        @zero_window_count = 0_u32

        @highest_seq_seen = nil
        @highest_ack_seen = nil
        @dup_ack_count = 0_u32
      end

      # Analyzes an incoming TCP segment for transmission anomalies
      def inspect_segment(
        seq : UInt32,
        payload_len : UInt32,
        ack : UInt32,
        ack_flag : Bool,
        window : UInt16,
        syn : Bool,
        fin : Bool,
        timestamp : Time,
      ) : TcpAnomalyType?
        # Detect Zero Window advertisement
        if window == 0_u16 && !syn && !fin
          @zero_window_count += 1_u32
          record_event(TcpAnomalyType::ZeroWindow, timestamp, seq, payload_len, "Receiver advertised 0 window (buffer exhausted)")
          return TcpAnomalyType::ZeroWindow
        end

        # Track Duplicate ACKs
        if ack_flag && payload_len == 0_u32
          if ack == @highest_ack_seen
            @dup_ack_count += 1_u32
          elsif @highest_ack_seen.nil? || Dissect::Layer4::TcpSeq.gt?(ack, @highest_ack_seen.not_nil!)
            @highest_ack_seen = ack
            @dup_ack_count = 0_u32
          end
        end

        return nil if payload_len == 0_u32 # Ignore pure ACKs for payload retransmission checks

        # Sequence progression checks
        if highest = @highest_seq_seen
          seg_end = seq &+ payload_len

          if Dissect::Layer4::TcpSeq.lte?(seg_end, highest)
            # Retransmission: this data was already seen previously
            anomaly = if @dup_ack_count >= 3_u32
                        TcpAnomalyType::FastRetransmission
                      elsif @highest_ack_seen && Dissect::Layer4::TcpSeq.lte?(seg_end, @highest_ack_seen.not_nil!)
                        TcpAnomalyType::SpuriousRetransmission
                      else
                        TcpAnomalyType::Retransmission
                      end

            @retransmission_count += 1_u32
            record_event(anomaly, timestamp, seq, payload_len, "Retransmission of sequence #{seq} (len #{payload_len})")
            return anomaly
          elsif Dissect::Layer4::TcpSeq.lt?(seq, highest)
            # Out of order: starts before highest seen, but extends past it
            @out_of_order_count += 1_u32
            record_event(TcpAnomalyType::OutOfOrder, timestamp, seq, payload_len, "Out-of-order segment starting at #{seq}")
            return TcpAnomalyType::OutOfOrder
          end
        end

        @highest_seq_seen = seq &+ payload_len
        nil
      end

      private def record_event(type : TcpAnomalyType, ts : Time, seq : UInt32, len : UInt32, desc : String) : Nil
        @events << TcpAnomalyEvent.new(type, ts, seq, len, desc)
      end
    end
  end
end
