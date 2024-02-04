# =============================================================================
# tcp_seq.cr - RFC 1982 Serial Number Arithmetic and TCP Sequence Tracking
# =============================================================================
#
# Because TCP sequence numbers are 32-bit unsigned integers that wrap around
# after 4 gigabytes of transfer, standard comparison operators (<, >, <=, >=)
# fail when sequence numbers wrap from 0xFFFFFFFF back to 0.
#
# RFC 1982 defines Serial Number Arithmetic where comparisons are defined on
# a circle of size 2^32. Sequence number A is considered "less than" B if and
# only if:
#     (B - A) in [1, 2^31 - 1] modulo 2^32
#
# This file provides modular sequence comparison primitives and tracks
# relative sequence numbers and duplicate acknowledgments.
#
# Author: filament contributors
# License: MIT
# =============================================================================

module Filament
  module Dissect
    module Layer4
      module TcpSeq
        # Modular sequence comparisons (RFC 1982)

        # Returns true if a is strictly before b in sequence space
        def self.lt?(a : UInt32, b : UInt32) : Bool
          diff = b &- a
          diff > 0_u32 && diff < 0x80000000_u32
        end

        # Returns true if a is less than or equal to b in sequence space
        def self.lte?(a : UInt32, b : UInt32) : Bool
          a == b || lt?(a, b)
        end

        # Returns true if a is strictly after b in sequence space
        def self.gt?(a : UInt32, b : UInt32) : Bool
          diff = a &- b
          diff > 0_u32 && diff < 0x80000000_u32
        end

        # Returns true if a is greater than or equal to b in sequence space
        def self.gte?(a : UInt32, b : UInt32) : Bool
          a == b || gt?(a, b)
        end

        # Signed distance between two sequence numbers (a - b)
        def self.diff(a : UInt32, b : UInt32) : Int64
          raw = a &- b
          if raw < 0x80000000_u32
            raw.to_i64
          else
            -((0_u32 &- raw).to_i64)
          end
        end

        # Normalizes an absolute sequence number relative to an Initial Sequence Number
        def self.to_relative(seq : UInt32, isn : UInt32) : UInt32
          seq &- isn
        end
      end

      # Tracks sequence state for a single unidirectional half of a TCP connection
      class TcpStreamTracker
        getter isn : UInt32?
        getter next_expected_seq : UInt32?
        getter highest_ack_seen : UInt32?
        getter dup_ack_count : UInt32
        getter bytes_delivered : UInt64

        def initialize
          @isn = nil
          @next_expected_seq = nil
          @highest_ack_seen = nil
          @dup_ack_count = 0_u32
          @bytes_delivered = 0_u64
        end

        # Records incoming segment sequence number and payload size
        def process_segment(seq : UInt32, payload_size : UInt32, syn : Bool, fin : Bool) : Nil
          # Establish ISN on SYN
          if syn && @isn.nil?
            @isn = seq
            @next_expected_seq = seq &+ 1_u32
            return
          end

          # If ISN was not captured (mid-stream capture), initialize with first observed seq
          if @isn.nil?
            @isn = seq
            @next_expected_seq = seq
          end

          current_expected = @next_expected_seq
          return unless current_expected

          # Advance next expected seq if contiguous
          if TcpSeq.lte?(seq, current_expected)
            end_seq = seq &+ payload_size &+ (fin ? 1_u32 : 0_u32)
            if TcpSeq.gt?(end_seq, current_expected)
              advance = (end_seq &- current_expected).to_u64
              @bytes_delivered += advance
              @next_expected_seq = end_seq
            end
          end
        end

        # Records incoming ACK number and tracks duplicate ACKs
        def process_ack(ack : UInt32) : Bool
          # Returns true if this is a duplicate ACK
          highest = @highest_ack_seen
          if highest.nil?
            @highest_ack_seen = ack
            @dup_ack_count = 0_u32
            return false
          end

          if ack == highest
            @dup_ack_count += 1_u32
            true
          elsif TcpSeq.gt?(ack, highest)
            @highest_ack_seen = ack
            @dup_ack_count = 0_u32
            false
          else
            # Old ACK, ignore
            false
          end
        end

        # Computes relative sequence number
        def relative_seq(seq : UInt32) : UInt32
          if init_seq = @isn
            TcpSeq.to_relative(seq, init_seq)
          else
            0_u32
          end
        end
      end
    end
  end
end
