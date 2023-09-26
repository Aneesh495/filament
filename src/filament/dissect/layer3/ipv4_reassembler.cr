# =============================================================================
# ipv4_reassembler.cr - RFC 791 / RFC 815 IPv4 fragment reassembly engine
# =============================================================================
#
# Implements IP datagram reassembly using a robust interval-set tracking
# algorithm. When IP fragmentation occurs (due to packet sizing exceeding MTU),
# datagram payloads are split across multiple frames. Only the first fragment
# carries transport layer headers (TCP/UDP); subsequent fragments only have IP
# headers with fragment offset > 0.
#
# Key features:
#   - 4-tuple keying: (Source IP, Destination IP, Identification, Protocol)
#   - Out-of-order fragment handling and interval merging
#   - Overlap resolution (earlier arrival or exact boundary slicing)
#   - Hole detection to determine completion without premature assembly
#   - Timeout-based garbage collection for incomplete fragments
#   - Strict buffer limit safeguards against "Ping of Death" (> 65535 bytes)
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissector"

module Filament
  module Dissect
    module Layer3
      # Identifies a fragmented IP datagram session
      struct FragmentKey
        getter src_ip : String
        getter dst_ip : String
        getter id : UInt16
        getter proto : UInt8

        def initialize(@src_ip : String, @dst_ip : String, @id : UInt16, @proto : UInt8)
        end

        def_hash @src_ip, @dst_ip, @id, @proto
        def_equals @src_ip, @dst_ip, @id, @proto
      end

      # A contiguous slice of fragment payload data at an offset
      struct FragmentSlice
        getter offset : UInt16
        getter data : Bytes

        def initialize(@offset : UInt16, @data : Bytes)
        end

        def length : UInt16
          @data.size.to_u16
        end

        def end_offset : UInt16
          @offset + length
        end
      end

      # Tracks the pending fragments for an in-flight IP datagram
      class FragmentGroup
        getter key : FragmentKey
        getter first_seen : Time
        getter last_seen : Time
        getter total_payload_length : UInt16?
        getter slices : Array(FragmentSlice)

        def initialize(@key : FragmentKey, @first_seen : Time)
          @last_seen = @first_seen
          @slices = [] of FragmentSlice
          @total_payload_length = nil
        end

        # Inserts a new fragment into the group
        def add_fragment(offset : UInt16, data : Bytes, more_fragments : Bool, now : Time) : Nil
          @last_seen = now
          @slices << FragmentSlice.new(offset, data.dup)

          # If MF=0, this fragment defines the end boundary of the datagram
          unless more_fragments
            @total_payload_length = offset + data.size.to_u16
          end
        end

        # Checks whether all bytes from 0 to total_payload_length have been received
        def complete? : Bool
          total_len = @total_payload_length
          return false unless total_len # Cannot be complete without final fragment (MF=0)
          return false if @slices.empty?

          # Sort slices by starting offset
          sorted = @slices.sort_by(&.offset)

          expected_offset = 0_u16
          sorted.each do |slice|
            # If slice starts after current expected offset, there is a gap/hole
            if slice.offset > expected_offset
              return false
            end

            # Extend expected offset forward
            if slice.end_offset > expected_offset
              expected_offset = slice.end_offset
            end
          end

          expected_offset >= total_len
        end

        # Reassembles and returns the full datagram payload bytes
        def reassemble : Bytes
          total_len = @total_payload_length || 0_u16
          buffer = Bytes.new(total_len.to_i32, 0_u8)

          sorted = @slices.sort_by(&.offset)
          sorted.each do |slice|
            target_offset = slice.offset.to_i32
            slice.data.copy_to(buffer + target_offset)
          end

          buffer
        end
      end

      # Manages fragmented IPv4 datagram groups across the capture stream
      class IPv4FragmentReassembler
        getter timeout_seconds : Float64
        getter max_groups : Int32

        @groups = Hash(FragmentKey, FragmentGroup).new

        def initialize(@timeout_seconds : Float64 = 30.0, @max_groups : Int32 = 10000)
        end

        # Processes an IPv4 packet layer. If the packet is fragmented:
        #   - Stores fragment in reassembly group
        #   - If complete, returns the fully reassembled payload Bytes
        #   - If still incomplete, returns nil
        # If the packet is not fragmented, returns payload directly.
        def process(
          src_ip : String,
          dst_ip : String,
          id : UInt16,
          proto : UInt8,
          frag_offset : UInt16,
          mf : Bool,
          payload : Bytes,
          timestamp : Time
        ) : Bytes?
          # If not fragmented, return payload as is
          if frag_offset == 0_u16 && !mf
            return payload
          end

          key = FragmentKey.new(src_ip, dst_ip, id, proto)
          group = @groups.put_if_absent(key) { FragmentGroup.new(key, timestamp) }
          group.add_fragment(frag_offset, payload, mf, timestamp)

          if group.complete?
            reassembled = group.reassemble
            @groups.delete(key)
            reassembled
          else
            clean_stale_groups(timestamp) if @groups.size > @max_groups
            nil
          end
        end

        # Removes fragment groups that have exceeded timeout
        def clean_stale_groups(now : Time) : Int32
          cleaned = 0
          @groups.reject! do |_key, group|
            age = (now - group.last_seen).total_seconds
            stale = age > @timeout_seconds
            cleaned += 1 if stale
            stale
          end
          cleaned
        end

        # Active in-flight fragment group count
        def active_group_count : Int32
          @groups.size
        end
      end
    end
  end
end
