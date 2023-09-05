# =============================================================================
# mmap_reader.cr - Memory-mapped zero-copy PCAP trace reader
# =============================================================================
#
# For multi-gigabyte capture files, standard stream IO introduces significant
# overhead through kernel-to-userspace buffer copying and repeated read syscalls.
#
# The MmapPcapReader maps the entire file (or rolling windows) directly into the
# process virtual address space via mmap(2). Packet payload slices point
# directly to pages cached by the OS page cache, eliminating memory allocations
# and copies along the critical packet path.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./packet"
require "./pcap"

module Filament
  module Capture
    # POSIX mmap flags and protection constants
    lib LibMman
      PROT_READ = 0x01
      MAP_SHARED = 0x0001
      MAP_PRIVATE = 0x0002

      fun mmap(addr : Void*, length : LibC::SizeT, prot : LibC::Int, flags : LibC::Int, fd : LibC::Int, offset : LibC::OffT) : Void*
      fun munmap(addr : Void*, length : LibC::SizeT) : LibC::Int
      fun madvise(addr : Void*, length : LibC::SizeT, advice : LibC::Int) : LibC::Int
    end

    MADV_SEQUENTIAL = 2 # Kernel readahead optimization hint

    # Zero-copy memory mapped PCAP reader
    class MmapPcapReader
      include Enumerable(RawPacket)

      getter file_size : Int64
      getter packet_count : UInt64
      getter link_type : LinkType
      getter snap_len : UInt32
      getter? little_endian : Bool
      getter? nanosecond_timestamps : Bool

      @file : File
      @base_ptr : UInt8*
      @cursor : Int64

      def initialize(path : String)
        @file = File.open(path, "r")
        @file_size = @file.size
        @packet_count = 0U64
        @cursor = 0L

        if @file_size < 24
          @file.close
          raise PcapError.new("File size #{@file_size} bytes is too short for PCAP global header")
        end

        fd = @file.fd
        mapped = LibMman.mmap(
          Pointer(Void).null,
          @file_size.to_u64,
          LibMman::PROT_READ,
          LibMman::MAP_PRIVATE,
          fd,
          0_i64
        )

        if mapped == Pointer(Void).new(-1_i64.to_u64)
          @file.close
          raise PcapError.new("Failed to mmap #{path} (errno: #{Errno.value})")
        end

        @base_ptr = mapped.as(UInt8*)
        # Advise the kernel we will traverse sequentially
        LibMman.madvise(mapped, @file_size.to_u64, MADV_SEQUENTIAL)

        # Parse global header (24 bytes)
        magic = read_u32_raw(0L)
        case magic
        when PcapMagic::IDENTICAL_MICRO
          @little_endian = true
          @nanosecond_timestamps = false
        when PcapMagic::SWAPPED_MICRO
          @little_endian = false
          @nanosecond_timestamps = false
        when PcapMagic::IDENTICAL_NANO
          @little_endian = true
          @nanosecond_timestamps = true
        when PcapMagic::SWAPPED_NANO
          @little_endian = false
          @nanosecond_timestamps = true
        else
          close
          raise InvalidMagicError.new("Invalid PCAP magic: 0x#{magic.to_s(16)}")
        end

        # Read snaplen at offset 16 and linktype at offset 20
        @snap_len = read_u32(16L)
        link_type_code = read_u32(20L)
        @link_type = LinkType.from_value?(link_type_code.to_i32) || LinkType::ETHERNET
        @cursor = 24L
      end

      # Yields each packet, creating a Slice referencing mapped memory directly
      def each(& : RawPacket ->)
        while @cursor + 16L <= @file_size
          ts_sec = read_u32(@cursor)
          ts_subsec = read_u32(@cursor + 4L)
          cap_len = read_u32(@cursor + 8L)
          orig_len = read_u32(@cursor + 12L)

          @cursor += 16L

          if @cursor + cap_len > @file_size
            break # File truncated
          end

          # Create a zero-copy Slice pointing directly into mapped memory
          packet_data = Slice.new(@base_ptr + @cursor, cap_len.to_i32)
          @cursor += cap_len

          timestamp = if @nanosecond_timestamps
                        Time.unix(ts_sec.to_i64) + Time::Span.new(nanoseconds: ts_subsec.to_i32)
                      else
                        Time.unix(ts_sec.to_i64) + Time::Span.new(nanoseconds: ts_subsec.to_i32 * 1_000)
                      end

          @packet_count += 1U64

          yield RawPacket.new(
            data: packet_data,
            timestamp: timestamp,
            original_length: orig_len,
            captured_length: cap_len,
            link_type: @link_type,
            interface_id: 0U32
          )
        end
      end

      # Resets cursor to read from beginning of packets
      def rewind : Nil
        @cursor = 24L
      end

      # Reads a 32-bit unsigned int at byte offset without endianness modification
      private def read_u32_raw(offset : Int64) : UInt32
        ptr = (@base_ptr + offset).as(UInt32*)
        ptr.value
      end

      # Reads a 32-bit unsigned int at byte offset respecting capture endianness
      private def read_u32(offset : Int64) : UInt32
        raw = read_u32_raw(offset)
        if @little_endian
          # Native is little endian on arm64 and x86_64
          raw
        else
          swap32(raw)
        end
      end

      private def swap32(v : UInt32) : UInt32
        ((v >> 24) & 0x000000FFU32) |
        ((v >> 8) & 0x0000FF00U32) |
        ((v << 8) & 0x00FF0000U32) |
        ((v << 24) & 0xFF000000U32)
      end

      # Unmaps memory and closes underlying file
      def close : Nil
        if @base_ptr != Pointer(UInt8).null
          LibMman.munmap(@base_ptr.as(Void*), @file_size.to_u64)
          @base_ptr = Pointer(UInt8).null
        end
        @file.close unless @file.closed?
      end

      def finalize
        close
      end
    end
  end
end
