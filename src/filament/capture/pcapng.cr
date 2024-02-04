# =============================================================================
# pcapng.cr - PCAP Next Generation file format reader and parser
# =============================================================================
#
# Implements the PCAP Next Generation (pcapng) file format specification
# as defined by the IETF / tcpdump.org drafts. Pcapng addresses many of the
# structural limitations of classic pcap:
#
#   1. Multiple interfaces per file, each with distinct link-layer headers,
#      snap lengths, and timestamp resolutions (e.g. nanoseconds vs microseconds).
#   2. Extensible block structure with forward and backward size fields,
#      allowing parsers to skip unrecognised blocks safely.
#   3. Embedded interface statistics (packets received, dropped by interface).
#   4. Name resolution tables (DNS/IP mappings embedded directly in capture).
#   5. Arbitrary options per block (comments, hardware strings, filter strings).
#
# File structure:
# A pcapng file is a sequence of blocks. Every file starts with a Section
# Header Block (SHB). Inside a section, one or more Interface Description
# Blocks (IDBs) define the interfaces (numbered implicitly starting from 0).
# Following the IDBs, packets arrive as Enhanced Packet Blocks (EPBs) or
# Simple Packet Blocks (SPBs).
#
# Block layout (general):
#   +------------------------------------+
#   |        Block Type (32 bits)        |
#   +------------------------------------+
#   |       Block Length (32 bits)       |
#   +------------------------------------+
#   /             Block Body             /
#   +------------------------------------+
#   |       Block Length (32 bits)       |
#   +------------------------------------+
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./packet"

module Filament
  module Capture
    # Standard block types defined in the pcapng specification
    module PcapngBlockType
      SECTION_HEADER       = 0x0A0D0D0A_u32
      INTERFACE_DESC       = 0x00000001_u32
      PACKET               = 0x00000002_u32 # Deprecated in favor of EPB
      SIMPLE_PACKET        = 0x00000003_u32
      NAME_RESOLUTION      = 0x00000004_u32
      INTERFACE_STATISTICS = 0x00000005_u32
      ENHANCED_PACKET      = 0x00000006_u32
      CUSTOM_COPYABLE      = 0x00000BAD_u32
      CUSTOM_NON_COPYABLE  = 0x40000BAD_u32
    end

    # Byte order magic values found inside Section Header Blocks
    module PcapngByteOrder
      LITTLE_ENDIAN = 0x1A2B3C4D_u32
      BIG_ENDIAN    = 0x4D3C2B1A_u32
    end

    # Generic option codes common across all pcapng block types
    module PcapngOptionCode
      END_OF_OPT = 0x0000_u16
      COMMENT    = 0x0001_u16

      # Interface Description Block options
      IF_NAME        = 0x0002_u16
      IF_DESCRIPTION = 0x0003_u16
      IF_IPV4ADDR    = 0x0004_u16
      IF_IPV6ADDR    = 0x0005_u16
      IF_MACADDR     = 0x0006_u16
      IF_EUIADDR     = 0x0007_u16
      IF_SPEED       = 0x0008_u16
      IF_TSRESOL     = 0x0009_u16
      IF_TZONE       = 0x000A_u16
      IF_FILTER      = 0x000B_u16
      IF_OS          = 0x000C_u16
      IF_FCSLEN      = 0x000D_u16
      IF_TSOFFSET    = 0x000E_u16

      # Enhanced Packet Block options
      EPB_FLAGS     = 0x0002_u16
      EPB_HASH      = 0x0003_u16
      EPB_DROPCOUNT = 0x0004_u16
    end

    # Represents an interface discovered within an Interface Description Block
    class PcapngInterface
      getter index : UInt32
      getter link_type : LinkType
      getter snap_len : UInt32
      getter name : String?
      getter description : String?
      getter ts_resolution : UInt8
      getter ts_is_power_of_two : Bool

      def initialize(
        @index : UInt32,
        @link_type : LinkType,
        @snap_len : UInt32,
        @name : String? = nil,
        @description : String? = nil,
        @ts_resolution : UInt8 = 6_u8, # Default to 10^-6 (microseconds)
        @ts_is_power_of_two : Bool = false,
      )
      end

      # Calculates time multiplier to convert raw 64-bit timestamp to seconds and nanoseconds
      def timestamp_to_time(raw_ts : UInt64) : Time
        if @ts_is_power_of_two
          # Value is negative power of 2: 2^-res seconds
          # Example: res=10 means units of 2^-10 = 1/1024 s
          scale = 2.0 ** (-@ts_resolution.to_f64)
          seconds = (raw_ts.to_f64 * scale).to_i64
          nanos = ((raw_ts.to_f64 * scale - seconds.to_f64) * 1_000_000_000.0).to_i32
          Time.unix(seconds) + Time::Span.new(nanoseconds: nanos)
        else
          # Value is negative power of 10: 10^-res seconds
          # res=6 is microseconds, res=9 is nanoseconds
          case @ts_resolution
          when 6
            # Microseconds
            sec = (raw_ts // 1_000_000_u64).to_i64
            usec = (raw_ts % 1_000_000_u64).to_i32
            Time.unix(sec) + Time::Span.new(nanoseconds: usec * 1_000)
          when 9
            # Nanoseconds
            sec = (raw_ts // 1_000_000_000_u64).to_i64
            nsec = (raw_ts % 1_000_000_000_u64).to_i32
            Time.unix(sec) + Time::Span.new(nanoseconds: nsec)
          else
            divisor = 10_u64 ** @ts_resolution
            sec = (raw_ts // divisor).to_i64
            remainder = (raw_ts % divisor).to_f64 / divisor.to_f64
            nsec = (remainder * 1_000_000_000.0).to_i32
            Time.unix(sec) + Time::Span.new(nanoseconds: nsec)
          end
        end
      end
    end

    # Error raised when parsing corrupt or non-conformant pcapng structures
    class PcapngError < Exception
    end

    # High performance streaming reader for PCAP Next Generation files
    class PcapngReader
      include Enumerable(RawPacket)

      getter interfaces : Array(PcapngInterface)
      getter? little_endian : Bool
      getter section_count : UInt32
      getter packet_count : UInt64

      def initialize(@io : IO)
        @interfaces = [] of PcapngInterface
        @little_endian = true
        @section_count = 0_u32
        @packet_count = 0_u64
        read_initial_section
      end

      # Convenience constructor opening a file by path
      def self.open(path : String, &)
        File.open(path, "rb") do |file|
          reader = new(file)
          yield reader
        end
      end

      # Yields each packet in order across all sections and interfaces
      def each(& : RawPacket ->)
        loop do
          packet = read_next_packet
          break unless packet
          @packet_count += 1_u64
          yield packet
        end
      end

      # Reads the initial section header to establish endianness
      private def read_initial_section : Nil
        block_type = read_u32
        unless block_type == PcapngBlockType::SECTION_HEADER
          raise PcapngError.new("Invalid pcapng magic: expected SHB (0x0A0D0D0A), got 0x#{block_type.to_s(16)}")
        end

        block_len = read_u32_le
        bom = read_u32_le

        if bom == PcapngByteOrder::LITTLE_ENDIAN
          @little_endian = true
        elsif bom == PcapngByteOrder::BIG_ENDIAN
          @little_endian = false
        else
          raise PcapngError.new("Unrecognized Byte Order Magic in SHB: 0x#{bom.to_s(16)}")
        end

        # Read section header body:
        # Major (u16), Minor (u16), Section Length (i64)
        _major = read_u16
        _minor = read_u16
        _section_len = read_i64

        # Skip options until trailing block_len
        # Total fixed header size so far: 4 (type) + 4 (len) + 4 (bom) + 2 (maj) + 2 (min) + 8 (len) + 4 (trailing len) = 28 bytes
        options_len = block_len.to_i32 - 28
        if options_len > 0
          skip_bytes(options_len)
        end

        trailing_len = read_u32
        if trailing_len != block_len
          raise PcapngError.new("Corrupted SHB: leading length #{block_len} != trailing length #{trailing_len}")
        end

        @section_count += 1_u32
      end

      # Reads the next packet block, skipping metadata or configuration blocks
      def read_next_packet : RawPacket?
        loop do
          return nil if @io.peek.empty? && @io.pos >= @io.size rescue nil

          # Attempt to read block type
          block_type_raw = read_u32_or_nil
          return nil unless block_type_raw

          block_len = read_u32
          if block_len < 12_u32
            raise PcapngError.new("Invalid block length #{block_len} (minimum is 12 bytes)")
          end

          case block_type_raw
          when PcapngBlockType::SECTION_HEADER
            parse_new_section(block_len)
          when PcapngBlockType::INTERFACE_DESC
            parse_interface_description(block_len)
          when PcapngBlockType::ENHANCED_PACKET
            return parse_enhanced_packet(block_len)
          when PcapngBlockType::SIMPLE_PACKET
            return parse_simple_packet(block_len)
          else
            # Unknown or non-packet block (Name Resolution, Interface Stats, etc.)
            body_len = block_len.to_i32 - 12
            skip_bytes(body_len) if body_len > 0
            _trailing = read_u32
          end
        end
      end

      # Handles switching sections within a multi-section pcapng capture
      private def parse_new_section(block_len : UInt32) : Nil
        bom = read_u32_le
        if bom == PcapngByteOrder::LITTLE_ENDIAN
          @little_endian = true
        elsif bom == PcapngByteOrder::BIG_ENDIAN
          @little_endian = false
        end

        _major = read_u16
        _minor = read_u16
        _section_len = read_i64

        options_len = block_len.to_i32 - 28
        skip_bytes(options_len) if options_len > 0
        _trailing = read_u32

        # Reset interfaces for the new section as per specification
        @interfaces.clear
        @section_count += 1_u32
      end

      # Parses an Interface Description Block and records interface parameters
      private def parse_interface_description(block_len : UInt32) : Nil
        link_type_code = read_u16
        _reserved = read_u16
        snap_len = read_u32

        link_type = LinkType.from_value?(link_type_code.to_i32) || LinkType::Ethernet

        # Parse options
        options_len = block_len.to_i32 - 20 # 4 type + 4 len + 2 link + 2 res + 4 snap + 4 trailing len
        name : String? = nil
        desc : String? = nil
        tsresol = 6_u8
        is_power_of_two = false

        if options_len > 0
          bytes_read = 0
          while bytes_read < options_len
            opt_code = read_u16
            opt_len = read_u16
            bytes_read += 4

            if opt_code == PcapngOptionCode::END_OF_OPT
              remaining = options_len - bytes_read
              skip_bytes(remaining) if remaining > 0
              break
            end

            opt_value = Bytes.new(opt_len.to_i32)
            @io.read_fully(opt_value)
            bytes_read += opt_len.to_i32

            # Options are padded to 32-bit boundaries
            padding = (4 - (opt_len % 4)) % 4
            if padding > 0
              skip_bytes(padding)
              bytes_read += padding
            end

            case opt_code
            when PcapngOptionCode::IF_NAME
              name = String.new(opt_value)
            when PcapngOptionCode::IF_DESCRIPTION
              desc = String.new(opt_value)
            when PcapngOptionCode::IF_TSRESOL
              if opt_len >= 1
                raw_resol = opt_value[0]
                is_power_of_two = (raw_resol & 0x80_u8) != 0_u8
                tsresol = raw_resol & 0x7F_u8
              end
            end
          end
        end

        _trailing = read_u32

        interface_idx = @interfaces.size.to_u32
        @interfaces << PcapngInterface.new(
          index: interface_idx,
          link_type: link_type,
          snap_len: snap_len,
          name: name,
          description: desc,
          ts_resolution: tsresol,
          ts_is_power_of_two: is_power_of_two
        )
      end

      # Parses an Enhanced Packet Block (EPB)
      private def parse_enhanced_packet(block_len : UInt32) : RawPacket
        interface_id = read_u32
        ts_high = read_u32.to_u64
        ts_low = read_u32.to_u64
        cap_len = read_u32
        orig_len = read_u32

        raw_ts = (ts_high << 32) | ts_low

        # Resolve timestamp using interface configuration
        iface = @interfaces.find { |i| i.index == interface_id }
        timestamp = if iface
                      iface.timestamp_to_time(raw_ts)
                    else
                      # Fallback assuming microseconds
                      sec = (raw_ts // 1_000_000_u64).to_i64
                      usec = (raw_ts % 1_000_000_u64).to_i32
                      Time.unix(sec) + Time::Span.new(nanoseconds: usec * 1_000)
                    end

        packet_data = Bytes.new(cap_len.to_i32)
        @io.read_fully(packet_data)

        # Skip packet padding to 32-bit boundary
        padding = (4 - (cap_len % 4)) % 4
        skip_bytes(padding.to_i32) if padding > 0

        # Skip options
        # Header size: 4 (type) + 4 (len) + 4 (if_id) + 8 (ts) + 4 (cap) + 4 (orig) + cap_len + pad + 4 (trailing)
        consumed = 28 + cap_len.to_i32 + padding.to_i32 + 4
        options_len = block_len.to_i32 - consumed
        skip_bytes(options_len) if options_len > 0

        _trailing = read_u32

        link_type = iface ? iface.link_type : LinkType::Ethernet

        RawPacket.new(
          data: packet_data,
          timestamp: timestamp,
          original_length: orig_len,
          captured_length: cap_len,
          link_type: link_type,
          interface_id: interface_id
        )
      end

      # Parses a Simple Packet Block (SPB)
      private def parse_simple_packet(block_len : UInt32) : RawPacket
        orig_len = read_u32
        cap_len = [orig_len, block_len - 16_u32].min

        packet_data = Bytes.new(cap_len.to_i32)
        @io.read_fully(packet_data)

        padding = (4 - (cap_len % 4)) % 4
        skip_bytes(padding.to_i32) if padding > 0

        _trailing = read_u32

        # SPB always implicitly maps to interface 0
        iface = @interfaces.first?
        link_type = iface ? iface.link_type : LinkType::Ethernet

        RawPacket.new(
          data: packet_data,
          timestamp: Time.utc,
          original_length: orig_len,
          captured_length: cap_len,
          link_type: link_type,
          interface_id: 0_u32
        )
      end

      # Helper for reading 16-bit integers adhering to endianness
      private def read_u16 : UInt16
        val = @io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)
        @little_endian ? val : ((val >> 8) | ((val & 0xFF_u16) << 8))
      end

      # Helper for reading 32-bit integers adhering to endianness
      private def read_u32 : UInt32
        val = @io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
        @little_endian ? val : swap32(val)
      end

      # Reads u32 returning nil at EOF
      private def read_u32_or_nil : UInt32?
        buf = uninitialized UInt8[4]
        read = @io.read(buf.to_slice)
        return nil if read < 4
        val = IO::ByteFormat::LittleEndian.decode(UInt32, buf.to_slice)
        @little_endian ? val : swap32(val)
      end

      # Always reads 32-bit little endian (for BOM and initial block type)
      private def read_u32_le : UInt32
        @io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
      end

      # Helper for reading 64-bit signed integers
      private def read_i64 : Int64
        val = @io.read_bytes(Int64, IO::ByteFormat::LittleEndian)
        @little_endian ? val : swap64(val.to_u64).to_i64
      end

      # Byte swapping utilities
      private def swap32(val : UInt32) : UInt32
        ((val >> 24) & 0x000000FF_u32) |
          ((val >> 8) & 0x0000FF00_u32) |
          ((val << 8) & 0x00FF0000_u32) |
          ((val << 24) & 0xFF000000_u32)
      end

      private def swap64(val : UInt64) : UInt64
        ((val >> 56) & 0x00000000000000FF_u64) |
          ((val >> 40) & 0x000000000000FF00_u64) |
          ((val >> 24) & 0x0000000000FF0000_u64) |
          ((val >> 8) & 0x00000000FF000000_u64) |
          ((val << 8) & 0x000000FF00000000_u64) |
          ((val << 24) & 0x0000FF0000000000_u64) |
          ((val << 40) & 0x00FF000000000000_u64) |
          ((val << 56) & 0xFF00000000000000_u64)
      end

      # Safely skip n bytes in the input stream
      private def skip_bytes(count : Int32) : Nil
        return if count <= 0
        @io.skip(count)
      end
    end
  end
end
