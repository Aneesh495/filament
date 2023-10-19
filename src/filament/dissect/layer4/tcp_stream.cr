# =============================================================================
# tcp_stream.cr - TCP out-of-order segment reassembly engine
# =============================================================================
#
# Because network packets can traverse asymmetric paths, encounter queueing
# delays, or suffer packet loss and retransmission, TCP segments regularly
# arrive out of order, duplicated, or overlapping.
#
# Application-layer protocols (HTTP, TLS, SMTP) operate on an ordered,
# contiguous byte stream. The TcpStreamReassembler buffers out-of-order segments
# into an ordered interval map, slices off duplicate overlapping prefixes,
# and drains contiguous bytes as soon as intervening sequence holes close.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./tcp_seq"

module Filament
  module Dissect
    module Layer4
      # An individual buffered segment waiting for contiguous drainage
      class BufferedSegment
        getter seq : UInt32
        getter data : Bytes

        def initialize(@seq : UInt32, @data : Bytes)
        end

        def length : UInt32
          @data.size.to_u32
        end

        def end_seq : UInt32
          @seq &+ length
        end
      end

      # Assembles ordered byte streams from out-of-order TCP segments
      class TcpStreamReassembler
        getter next_seq : UInt32?
        getter max_buffer_bytes : Int32
        getter buffered_bytes : Int32
        getter segments : Array(BufferedSegment)

        def initialize(@max_buffer_bytes : Int32 = 4_000_000)
          @next_seq = nil
          @buffered_bytes = 0
          @segments = [] of BufferedSegment
        end

        # Feeds an incoming segment into the reassembler.
        # Returns newly available in-order contiguous Bytes (or empty slice if no bytes ready).
        def push(seq : UInt32, payload : Bytes, syn : Bool = false) : Bytes
          return Bytes.empty if payload.empty? && !syn

          # Initialize baseline sequence on SYN or first received segment
          if @next_seq.nil?
            @next_seq = syn ? (seq &+ 1_u32) : seq
            return Bytes.empty if payload.empty?
          end

          current_expected = @next_seq.not_nil!
          seg_end = seq &+ payload.size.to_u32

          # Segment is completely in the past (duplicate / retransmission)
          if TcpSeq.lte?(seg_end, current_expected)
            return Bytes.empty
          end

          # If segment starts before expected, slice off already-received prefix
          effective_seq = seq
          effective_data = payload

          if TcpSeq.lt?(seq, current_expected)
            skip = (current_expected &- seq).to_i32
            effective_seq = current_expected
            effective_data = payload[skip..]
          end

          # If this segment exactly meets our next expected sequence, drain it immediately
          if effective_seq == current_expected
            drained_chunks = [effective_data]
            @next_seq = effective_seq &+ effective_data.size.to_u32

            # Check if any previously buffered segments can now be drained
            drain_buffered(drained_chunks)

            # Concatenate all drained chunks into a contiguous slice
            total_size = drained_chunks.sum(&.size)
            result = Bytes.new(total_size)
            write_pos = 0
            drained_chunks.each do |chunk|
              chunk.copy_to(result + write_pos)
              write_pos += chunk.size
            end

            return result
          end

          # Otherwise, segment is in the future (out of order), buffer it
          insert_buffered(effective_seq, effective_data)
          Bytes.empty
        end

        # Inserts segment into buffered list maintaining sequence order
        private def insert_buffered(seq : UInt32, data : Bytes) : Nil
          return if @buffered_bytes + data.size > @max_buffer_bytes

          buf_seg = BufferedSegment.new(seq, data.dup)
          @segments << buf_seg
          @buffered_bytes += data.size

          # Keep sorted by sequence number
          @segments.sort_by! { |s| s.seq }
        end

        # Drains contiguous buffered segments following the advance of next_seq
        private def drain_buffered(drained_chunks : Array(Bytes)) : Nil
          return if @segments.empty?

          loop do
            break if @segments.empty?
            expected = @next_seq.not_nil!

            first = @segments.first
            if TcpSeq.lte?(first.seq, expected)
              # Check if segment extends beyond current expected
              if TcpSeq.gt?(first.end_seq, expected)
                skip = (expected &- first.seq).to_i32
                ready_slice = first.data[skip..]
                drained_chunks << ready_slice
                @next_seq = expected &+ ready_slice.size.to_u32
              end

              @buffered_bytes -= first.data.size
              @segments.shift
            else
              # Gap detected, cannot drain further
              break
            end
          end
        end

        # Discards all buffered segments
        def reset : Nil
          @segments.clear
          @buffered_bytes = 0
          @next_seq = nil
        end
      end
    end
  end
end
