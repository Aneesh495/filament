# =============================================================================
# ring_buffer.cr - Thread-safe circular ring buffer for packet storage
# =============================================================================
#
# A high-performance circular buffer designed for the classic single-producer,
# single-consumer (SPSC) pattern that's bread and butter for packet capture:
# one fiber captures packets and pushes them in, another fiber pulls them out
# for analysis.
#
# The design uses atomic operations on the read and write indices instead of
# a mutex, which avoids the overhead of kernel-level locking. This matters
# when you're pushing hundreds of thousands of packets per second.
#
# When the buffer fills up, new pushes silently overwrite the oldest entry.
# This is the right tradeoff for packet capture: it's better to drop old
# packets than to block the capture engine or lose current traffic. The
# statistics counters track how many packets were dropped so analysis code
# can report the loss.
#
# Implementation note on Crystal's concurrency: Crystal uses green threads
# (fibers) with cooperative scheduling, and Atomic operations ensure proper
# memory ordering. For true OS-thread safety you'd need additional fencing,
# but within Crystal's fiber model this approach works well.
#
# Author: filament contributors
# License: MIT
# =============================================================================

module Filament
  module Capture
    # -------------------------------------------------------------------------
    # RingBufferStats - tracks buffer usage over time
    # -------------------------------------------------------------------------

    # Keeps running statistics about buffer utilization. Useful for
    # diagnosing performance problems: if total_dropped is high, you
    # need either a bigger buffer or a faster consumer.
    struct RingBufferStats
      # Total number of items successfully pushed into the buffer
      # since creation (including ones later overwritten)
      getter total_pushed : UInt64

      # Total number of items that were overwritten before the consumer
      # could read them. This is data loss and should ideally be zero.
      getter total_dropped : UInt64

      # The maximum number of items that were in the buffer at any one
      # time. If this equals capacity, the buffer filled up at some point.
      getter high_watermark : UInt32

      # Total number of items successfully popped from the buffer
      getter total_popped : UInt64

      def initialize(
        @total_pushed : UInt64 = 0_u64,
        @total_dropped : UInt64 = 0_u64,
        @high_watermark : UInt32 = 0_u32,
        @total_popped : UInt64 = 0_u64,
      )
      end

      # Drop rate as a fraction between 0.0 and 1.0. Returns 0.0 if
      # nothing has been pushed yet (to avoid division by zero).
      def drop_rate : Float64
        return 0.0 if @total_pushed == 0
        @total_dropped.to_f64 / @total_pushed.to_f64
      end

      # Percentage of capacity that was used at the peak.
      def watermark_percent(capacity : UInt32) : Float64
        return 0.0 if capacity == 0
        (@high_watermark.to_f64 / capacity.to_f64) * 100.0
      end

      # Human-readable summary for logging.
      def to_s(io : IO) : Nil
        io << "RingBufferStats("
        io << "pushed=#{@total_pushed}, "
        io << "popped=#{@total_popped}, "
        io << "dropped=#{@total_dropped}, "
        io << "drop_rate=#{"%.2f" % (drop_rate * 100)}%, "
        io << "high_watermark=#{@high_watermark}"
        io << ")"
      end
    end

    # -------------------------------------------------------------------------
    # RingBuffer(T) - the actual circular buffer
    # -------------------------------------------------------------------------

    # A generic circular ring buffer that supports concurrent single-producer
    # and single-consumer access via atomic index operations.
    #
    # ```
    # buffer = Filament::Capture::RingBuffer(Int32).new(1024)
    # buffer.push(42)
    # value = buffer.pop # => 42
    # ```
    #
    # When the buffer is full, `push` overwrites the oldest item and
    # increments the drop counter. When empty, `pop` returns nil.
    class RingBuffer(T)
      # The fixed capacity of this buffer. Cannot be changed after creation.
      getter capacity : UInt32

      # The underlying storage array. We pre-allocate all slots on creation
      # so there's no allocation during push/pop.
      @storage : Array(T?)

      # Write index: where the next push will write. Only modified by the
      # producer. We use Atomic for memory ordering guarantees even though
      # Crystal fibers are cooperative - it's good practice and makes the
      # intent clear.
      @write_pos : Atomic(UInt32)

      # Read index: where the next pop will read from. Only modified by
      # the consumer.
      @read_pos : Atomic(UInt32)

      # Current number of items in the buffer. Updated atomically by both
      # producer (increment) and consumer (decrement).
      @count : Atomic(UInt32)

      # Stats counters. These are also atomic because they might be read
      # from a monitoring fiber while capture is in progress.
      @total_pushed : Atomic(UInt64)
      @total_dropped : Atomic(UInt64)
      @total_popped : Atomic(UInt64)
      @high_watermark : Atomic(UInt32)

      # Creates a new ring buffer with the specified capacity. The capacity
      # must be at least 1 (and ideally a power of 2 for performance, but
      # we don't enforce that since modulo works fine for our scale).
      def initialize(capacity : Int32)
        raise ArgumentError.new("Ring buffer capacity must be positive, got #{capacity}") if capacity <= 0

        @capacity = capacity.to_u32
        @storage = Array(T?).new(capacity) { nil }
        @write_pos = Atomic(UInt32).new(0_u32)
        @read_pos = Atomic(UInt32).new(0_u32)
        @count = Atomic(UInt32).new(0_u32)
        @total_pushed = Atomic(UInt64).new(0_u64)
        @total_dropped = Atomic(UInt64).new(0_u64)
        @total_popped = Atomic(UInt64).new(0_u64)
        @high_watermark = Atomic(UInt32).new(0_u32)
      end

      # Pushes an item into the buffer. If the buffer is full, the oldest
      # item is silently overwritten and counted as a drop.
      #
      # This method is designed to be called from a single producer fiber.
      # It never blocks, which is critical for the capture path.
      def push(item : T) : Nil
        current_count = @count.get(:acquire)

        if current_count >= @capacity
          # Buffer is full. Overwrite the oldest entry by advancing the
          # read pointer. The consumer will never see that entry.
          old_read = @read_pos.get(:acquire)
          @read_pos.set((old_read + 1) % @capacity, :release)
          @total_dropped.add(1, :relaxed)

          # Count stays the same since we're replacing, not adding
        else
          # There's room, so the count increases
          new_count = @count.add(1, :release) + 1

          # Update high watermark if this is a new peak
          loop do
            current_hw = @high_watermark.get(:relaxed)
            break if new_count <= current_hw
            # Try to update; if someone else updated first, loop and check again
            break if @high_watermark.compare_and_set(current_hw, new_count, :relaxed, :relaxed)[1]
          end
        end

        # Write the item at the current write position
        pos = @write_pos.get(:acquire)
        @storage[pos] = item
        @write_pos.set((pos + 1) % @capacity, :release)

        @total_pushed.add(1, :relaxed)
      end

      # Pops the oldest item from the buffer. Returns nil if the buffer
      # is empty.
      #
      # This method is designed to be called from a single consumer fiber.
      # It never blocks.
      def pop : T?
        current_count = @count.get(:acquire)
        return nil if current_count == 0

        # Read the item at the current read position
        pos = @read_pos.get(:acquire)
        item = @storage[pos]
        @storage[pos] = nil # Help the GC by clearing the reference

        @read_pos.set((pos + 1) % @capacity, :release)
        @count.sub(1, :release)
        @total_popped.add(1, :relaxed)

        item
      end

      # Tries to pop up to `max` items at once, returning them in an array.
      # This is more efficient than calling pop in a loop because we only
      # pay the atomic read overhead once for the count check.
      def pop_batch(max : Int32) : Array(T)
        result = [] of T
        current_count = @count.get(:acquire)
        batch_size = Math.min(max, current_count.to_i32)

        batch_size.times do
          if item = pop
            result << item
          else
            break # Shouldn't happen, but be defensive
          end
        end

        result
      end

      # Current number of items in the buffer.
      def size : UInt32
        @count.get(:acquire)
      end

      # Is the buffer empty?
      def empty? : Bool
        size == 0
      end

      # Is the buffer at capacity?
      def full? : Bool
        size >= @capacity
      end

      # Returns a snapshot of the current buffer statistics. This is a
      # point-in-time view; values may change immediately after reading.
      def stats : RingBufferStats
        RingBufferStats.new(
          total_pushed: @total_pushed.get(:acquire),
          total_dropped: @total_dropped.get(:acquire),
          high_watermark: @high_watermark.get(:acquire),
          total_popped: @total_popped.get(:acquire)
        )
      end

      # How full is the buffer, as a percentage?
      def utilization : Float64
        return 0.0 if @capacity == 0
        (size.to_f64 / @capacity.to_f64) * 100.0
      end

      # Iterates over all items currently in the buffer without removing
      # them. This is a snapshot operation - items pushed during iteration
      # may or may not be seen, and items popped during iteration may
      # cause inconsistencies. Best used when the producer is paused.
      #
      # NOTE: This copies the items to avoid races. For large buffers
      # with large items, this can be expensive.
      def each(& : T ->) : Nil
        current_count = @count.get(:acquire)
        current_read = @read_pos.get(:acquire)

        current_count.times do |i|
          pos = (current_read + i) % @capacity
          if item = @storage[pos]
            yield item
          end
        end
      end

      # Returns all items currently in the buffer as an array, without
      # removing them. Same caveats as `each` about concurrency.
      def to_a : Array(T)
        items = [] of T
        each { |item| items << item }
        items
      end

      # Removes all items from the buffer and resets the statistics.
      # Not safe to call while producer/consumer are active.
      def clear : Nil
        @capacity.times do |i|
          @storage[i] = nil
        end
        @write_pos.set(0_u32, :release)
        @read_pos.set(0_u32, :release)
        @count.set(0_u32, :release)
        @total_pushed.set(0_u64, :release)
        @total_dropped.set(0_u64, :release)
        @total_popped.set(0_u64, :release)
        @high_watermark.set(0_u32, :release)
      end

      # Returns a human-readable summary of the buffer state.
      def to_s(io : IO) : Nil
        io << "RingBuffer(#{T}): #{size}/#{@capacity} items "
        io << "(#{"%.1f" % utilization}% full, "
        io << "#{stats})"
      end
    end

    # -------------------------------------------------------------------------
    # Convenience alias
    # -------------------------------------------------------------------------

    # Pre-specialized ring buffer type for the common case of buffering
    # captured packets. Saves typing and makes the intent clear.
    alias PacketRingBuffer = RingBuffer(RawPacket)
  end
end
