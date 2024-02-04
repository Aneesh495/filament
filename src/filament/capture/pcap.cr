# =============================================================================
# pcap.cr - PCAP file format reader and writer
# =============================================================================
#
# Implements the classic libpcap/tcpdump .pcap file format (RFC-ish, documented
# at https://wiki.wireshark.org/Development/LibpcapFileFormat). This is still
# the most widely used packet capture format, even though pcapng is technically
# its successor.
#
# The format is dead simple: a 24-byte global header followed by zero or more
# (16-byte packet header + packet data) pairs. The tricky part is endianness:
# the magic number at the start tells us whether the file was written on a
# big-endian or little-endian machine, and we need to byte-swap everything
# accordingly.
#
# We support both traditional microsecond timestamps (magic 0xa1b2c3d4) and
# the less common nanosecond variant (magic 0xa1b23c4d), though the nanosecond
# variant is rare in practice.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./packet"

module Filament
  module Capture
    # -------------------------------------------------------------------------
    # Error hierarchy for PCAP operations
    # -------------------------------------------------------------------------

    # Base error class for all PCAP-related failures. Every specific PCAP
    # error inherits from this so callers can rescue broadly if they want.
    class PcapError < Exception; end

    # Raised when the magic number at the start of a file doesn't match
    # any known PCAP magic value. This usually means the file isn't actually
    # a pcap, or it's been corrupted.
    class InvalidMagicError < PcapError
      getter found_magic : UInt32

      def initialize(@found_magic : UInt32)
        super("Invalid PCAP magic number: 0x#{@found_magic.to_s(16).rjust(8, '0')}. " \
              "Expected 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, or 0x4d3cb2a1.")
      end
    end

    # Raised when we hit EOF in the middle of reading a packet header or
    # packet data. This happens with truncated capture files, which are
    # surprisingly common (think: ctrl-c while capturing).
    class TruncatedPacketError < PcapError
      getter packet_number : UInt64
      getter expected_bytes : UInt32
      getter actual_bytes : UInt32

      def initialize(@packet_number : UInt64, @expected_bytes : UInt32, @actual_bytes : UInt32)
        super("Truncated packet ##{@packet_number}: expected #{@expected_bytes} bytes " \
              "but only got #{@actual_bytes}. File may be incomplete.")
      end
    end

    # -------------------------------------------------------------------------
    # Constants
    # -------------------------------------------------------------------------

    # Magic numbers identify the file as PCAP and tell us the byte order.
    # The "native" magic means the file was written on a machine with the
    # same endianness as ours; the "swapped" magic means we need to flip
    # every multi-byte field.

    # Standard PCAP magic - microsecond timestamp resolution
    PCAP_MAGIC_NATIVE  = 0xa1b2c3d4_u32
    PCAP_MAGIC_SWAPPED = 0xd4c3b2a1_u32

    # Nanosecond PCAP magic - same format but timestamps are in nanoseconds
    # instead of microseconds. Not super common but some tools produce it.
    PCAP_MAGIC_NANO_NATIVE  = 0xa1b23c4d_u32
    PCAP_MAGIC_NANO_SWAPPED = 0x4d3cb2a1_u32

    # Size of the global file header (magic + version + timezone + sigfigs +
    # snaplen + linktype), in bytes.
    PCAP_GLOBAL_HEADER_SIZE = 24

    # Size of each per-packet header (timestamp seconds + timestamp
    # microseconds + captured length + original length), in bytes.
    PCAP_PACKET_HEADER_SIZE = 16

    # -------------------------------------------------------------------------
    # Link type constants
    # -------------------------------------------------------------------------
    # These identify the type of link-layer header at the start of each
    # captured packet. The full list is enormous (see tcpdump.org/linktypes),
    # but we only support the ones that actually matter in practice.

    LINKTYPE_NULL       =   0_u32 # BSD loopback encapsulation
    LINKTYPE_ETHERNET   =   1_u32 # Good old Ethernet II
    LINKTYPE_RAW        = 101_u32 # Raw IP, no link-layer header
    LINKTYPE_LINUX_SLL  = 113_u32 # Linux "cooked" capture
    LINKTYPE_LINUX_SLL2 = 276_u32 # Linux "cooked" v2 (newer kernels)

    # -------------------------------------------------------------------------
    # PcapHeader - the 24-byte global file header
    # -------------------------------------------------------------------------

    # Represents the global header at the start of every PCAP file. This
    # tells us everything we need to know about how to interpret the rest
    # of the file: byte order, version, snap length, and link type.
    #
    # ```
    # reader = Filament::Capture::PcapReader.new("capture.pcap")
    # puts reader.header.link_type # => 1 (Ethernet)
    # puts reader.header.snaplen   # => 65535
    # ```
    struct PcapHeader
      # The magic number. In a properly read file this will always be
      # PCAP_MAGIC_NATIVE (we normalize it during reading).
      getter magic_number : UInt32

      # Major and minor version of the PCAP format. Almost always 2.4.
      # If you see anything else, something weird is going on.
      getter version_major : UInt16
      getter version_minor : UInt16

      # GMT to local timezone correction, in seconds. In practice this is
      # always zero because nobody actually sets it.
      getter thiszone : Int32

      # Accuracy of timestamps. Also always zero in practice. The PCAP
      # format spec was aspirational about precision tracking.
      getter sigfigs : UInt32

      # Maximum number of bytes captured per packet. Common values are
      # 65535 (capture everything) or 96 (just headers). Packets longer
      # than this get truncated.
      getter snaplen : UInt32

      # The link-layer header type. Determines how to parse the first
      # bytes of each packet. See LINKTYPE_* constants above.
      getter link_type : UInt32

      def initialize(
        @magic_number : UInt32,
        @version_major : UInt16,
        @version_minor : UInt16,
        @thiszone : Int32,
        @sigfigs : UInt32,
        @snaplen : UInt32,
        @link_type : UInt32,
      )
      end

      # Returns a human-readable description of the link type.
      def link_type_name : String
        case @link_type
        when LINKTYPE_NULL       then "Null/Loopback"
        when LINKTYPE_ETHERNET   then "Ethernet"
        when LINKTYPE_RAW        then "Raw IP"
        when LINKTYPE_LINUX_SLL  then "Linux Cooked Capture"
        when LINKTYPE_LINUX_SLL2 then "Linux Cooked Capture v2"
        else                          "Unknown (#{@link_type})"
        end
      end

      # Checks whether the file version is one we know how to read.
      # Currently we only support version 2.4, which is the only version
      # that has ever existed in the wild.
      def supported_version? : Bool
        @version_major == 2 && @version_minor == 4
      end

      # Creates a default header suitable for writing new PCAP files.
      # Defaults to Ethernet link type and a generous snap length.
      def self.default(link_type : UInt32 = LINKTYPE_ETHERNET, snaplen : UInt32 = 65535_u32) : PcapHeader
        PcapHeader.new(
          magic_number: PCAP_MAGIC_NATIVE,
          version_major: 2_u16,
          version_minor: 4_u16,
          thiszone: 0_i32,
          sigfigs: 0_u32,
          snaplen: snaplen,
          link_type: link_type
        )
      end
    end

    # -------------------------------------------------------------------------
    # PacketHeader - the 16-byte per-packet header
    # -------------------------------------------------------------------------

    # Each packet in a PCAP file is preceded by this header. It gives us
    # the timestamp and the lengths (both captured and original).
    #
    # The distinction between incl_len and orig_len is important: if the
    # snap length was smaller than the packet, incl_len < orig_len and
    # we only have a prefix of the packet data.
    struct PacketHeader
      # Timestamp seconds since Unix epoch (1970-01-01 00:00:00 UTC)
      getter ts_sec : UInt32

      # Timestamp sub-second component. Microseconds for standard PCAP,
      # nanoseconds for nanosecond-resolution PCAP files.
      getter ts_usec : UInt32

      # Number of bytes of packet data actually captured and saved in
      # the file. May be less than orig_len if snapping occurred.
      getter incl_len : UInt32

      # Original length of the packet as it appeared on the wire. This
      # is the "real" packet size before any truncation.
      getter orig_len : UInt32

      def initialize(@ts_sec : UInt32, @ts_usec : UInt32, @incl_len : UInt32, @orig_len : UInt32)
      end

      # Constructs a Crystal Time object from the packet timestamp.
      # For nanosecond-resolution files, you should pass `nano: true`
      # so we interpret ts_usec correctly.
      def to_time(nano : Bool = false) : Time
        if nano
          # ts_usec is actually nanoseconds
          seconds = @ts_sec.to_i64
          nanoseconds = @ts_usec.to_i32
        else
          # ts_usec is microseconds, convert to nanoseconds for Time
          seconds = @ts_sec.to_i64
          nanoseconds = (@ts_usec * 1000).to_i32
        end
        Time.unix(seconds) + Time::Span.new(nanoseconds: nanoseconds.to_i64)
      end

      # Was this packet truncated by the snap length?
      def truncated? : Bool
        @incl_len < @orig_len
      end
    end

    # -------------------------------------------------------------------------
    # PcapReader - reads packets from a PCAP file
    # -------------------------------------------------------------------------

    # Opens and reads PCAP capture files, yielding packets one at a time.
    # Automatically handles endianness detection and byte swapping.
    #
    # ```
    # reader = Filament::Capture::PcapReader.new("traffic.pcap")
    # reader.each_packet do |data, timestamp, orig_len|
    #   puts "#{timestamp}: #{data.size} bytes (#{orig_len} on wire)"
    # end
    # reader.close
    # ```
    class PcapReader
      include Enumerable(RawPacket)

      # The parsed global header from the file
      getter header : PcapHeader

      # Whether we need to swap bytes (file endianness differs from ours)
      getter swapped : Bool

      # Whether this is a nanosecond-resolution PCAP file
      getter nano : Bool

      # Track how many packets we've read (for error reporting)
      @packet_count : UInt64 = 0_u64

      # The underlying IO we're reading from
      @io : IO

      # Whether we own the IO and should close it
      @owns_io : Bool

      # Opens a PCAP file by path. The file is opened for reading and
      # will be closed when `close` is called.
      def self.new(path : String) : PcapReader
        io = File.open(path, "rb")
        new(io, owns_io: true)
      end

      # Opens a PCAP file by path and yields reader to block
      def self.open(path : String, &block : PcapReader ->)
        reader = new(path)
        begin
          yield reader
        ensure
          reader.close
        end
      end

      # Creates a reader from an existing IO object. If `owns_io` is
      # true, calling `close` will also close the underlying IO.
      def initialize(@io : IO, @owns_io : Bool = false)
        @swapped = false
        @nano = false
        @header = read_global_header
      end

      # Yields each packet as a RawPacket struct, satisfying Enumerable
      def each(&block : RawPacket ->)
        each_packet do |data, timestamp, orig_len|
          yield RawPacket.new(
            data: data.dup,
            timestamp: timestamp,
            original_length: orig_len,
            capture_length: data.size.to_u32,
            interface_id: 0_u32,
            link_type: LinkType.from_value(@header.link_type)
          )
        end
      end

      # Iterates over every packet in the file, yielding the raw packet
      # bytes, the timestamp as a Time object, and the original wire
      # length. This is the main workhorse method.
      #
      # If the file is truncated mid-packet, raises TruncatedPacketError
      # unless `ignore_truncated` is true, in which case it silently
      # stops iterating.
      def each_packet(ignore_truncated : Bool = false, &block : Bytes, Time, UInt32 ->)
        loop do
          pkt_header = read_packet_header
          break unless pkt_header # EOF, clean end of file

          @packet_count += 1

          # Sanity check: incl_len shouldn't exceed snaplen. Some broken
          # capture tools produce garbage lengths, so we cap it.
          incl_len = pkt_header.incl_len
          if incl_len > @header.snaplen
            incl_len = @header.snaplen
          end

          # Read the actual packet data
          data = Bytes.new(incl_len)
          bytes_read = @io.read(data)

          if bytes_read < incl_len
            if ignore_truncated
              break
            else
              raise TruncatedPacketError.new(
                @packet_count,
                incl_len,
                bytes_read.to_u32
              )
            end
          end

          timestamp = pkt_header.to_time(nano: @nano)
          yield data, timestamp, pkt_header.orig_len
        end
      end

      # Returns an iterator of RawPacket structs instead of yielding.
      # Useful when you want to collect packets into an array or chain
      # with other iterators.
      def packets(ignore_truncated : Bool = false) : Array(RawPacket)
        result = [] of RawPacket
        packet_num = 0_u32

        each_packet(ignore_truncated: ignore_truncated) do |data, timestamp, orig_len|
          packet_num += 1
          result << RawPacket.new(
            data: data.dup, # dup because the buffer gets reused
            timestamp: timestamp,
            original_length: orig_len,
            capture_length: data.size.to_u32,
            interface_id: 0_u32, # classic PCAP only has one interface
            link_type: LinkType.from_value(@header.link_type)
          )
        end

        result
      end

      # Resets the reader back to the first packet. Only works if the
      # underlying IO supports seeking (i.e., it's a file, not a pipe).
      def rewind
        @io.seek(PCAP_GLOBAL_HEADER_SIZE, IO::Seek::Set)
        @packet_count = 0_u64
      end

      # Number of packets read so far
      def packets_read : UInt64
        @packet_count
      end

      # Closes the reader and, if we own it, the underlying IO.
      def close
        @io.close if @owns_io
      end

      # -----------------------------------------------------------------------
      # Private helpers
      # -----------------------------------------------------------------------

      # Reads and validates the 24-byte global header at the start of
      # the file. This is where we figure out endianness and timestamp
      # resolution.
      private def read_global_header : PcapHeader
        # Read the magic number first to determine byte order
        raw_magic = read_u32_raw
        raise InvalidMagicError.new(raw_magic) unless valid_magic?(raw_magic)

        # Determine if we need to byte-swap based on the magic
        @swapped = (raw_magic == PCAP_MAGIC_SWAPPED || raw_magic == PCAP_MAGIC_NANO_SWAPPED)
        @nano = (raw_magic == PCAP_MAGIC_NANO_NATIVE || raw_magic == PCAP_MAGIC_NANO_SWAPPED)

        # Now read the rest of the header fields, swapping if needed
        version_major = read_u16
        version_minor = read_u16
        thiszone = read_i32
        sigfigs = read_u32
        snaplen = read_u32
        link_type = read_u32

        PcapHeader.new(
          magic_number: PCAP_MAGIC_NATIVE, # normalize to native
          version_major: version_major,
          version_minor: version_minor,
          thiszone: thiszone,
          sigfigs: sigfigs,
          snaplen: snaplen,
          link_type: link_type
        )
      end

      # Reads a single packet header. Returns nil on clean EOF (no bytes
      # available). Raises TruncatedPacketError if we get a partial header.
      private def read_packet_header : PacketHeader?
        # Try to read the first 4 bytes. If we get nothing, that's a
        # clean EOF and we just return nil.
        buf = Bytes.new(PCAP_PACKET_HEADER_SIZE)
        first_byte_count = @io.read(buf[0, 4])
        return nil if first_byte_count == 0

        # If we got some bytes but not all 16, that's a truncation
        if first_byte_count < 4
          raise TruncatedPacketError.new(@packet_count + 1, PCAP_PACKET_HEADER_SIZE.to_u32, first_byte_count.to_u32)
        end

        # Read the remaining 12 bytes
        remaining = @io.read(buf[4, 12])
        if remaining < 12
          raise TruncatedPacketError.new(@packet_count + 1, PCAP_PACKET_HEADER_SIZE.to_u32, (first_byte_count + remaining).to_u32)
        end

        # Parse the four 32-bit fields from the buffer
        io_buf = IO::Memory.new(buf)
        ts_sec = read_u32_from(io_buf)
        ts_usec = read_u32_from(io_buf)
        incl_len = read_u32_from(io_buf)
        orig_len = read_u32_from(io_buf)

        PacketHeader.new(ts_sec, ts_usec, incl_len, orig_len)
      end

      # Is this a recognized PCAP magic number?
      private def valid_magic?(magic : UInt32) : Bool
        magic == PCAP_MAGIC_NATIVE ||
          magic == PCAP_MAGIC_SWAPPED ||
          magic == PCAP_MAGIC_NANO_NATIVE ||
          magic == PCAP_MAGIC_NANO_SWAPPED
      end

      # Reads a raw 32-bit value without any swapping. Used only for
      # the initial magic number read.
      private def read_u32_raw : UInt32
        buf = Bytes.new(4)
        count = @io.read(buf)
        raise PcapError.new("Failed to read PCAP magic number: file too short") if count < 4
        IO::ByteFormat::LittleEndian.decode(UInt32, buf)
      end

      # Reads a 16-bit unsigned integer, swapping if the file has
      # opposite endianness.
      private def read_u16 : UInt16
        buf = Bytes.new(2)
        @io.read_fully(buf)
        value = IO::ByteFormat::LittleEndian.decode(UInt16, buf)
        @swapped ? value.byte_swap : value
      end

      # Reads a 32-bit unsigned integer, swapping if needed.
      private def read_u32 : UInt32
        buf = Bytes.new(4)
        @io.read_fully(buf)
        value = IO::ByteFormat::LittleEndian.decode(UInt32, buf)
        @swapped ? value.byte_swap : value
      end

      # Reads a 32-bit signed integer, swapping if needed.
      private def read_i32 : Int32
        read_u32.to_i32!
      end

      # Reads a 32-bit unsigned integer from a given IO, with swap awareness.
      private def read_u32_from(io : IO) : UInt32
        buf = Bytes.new(4)
        io.read_fully(buf)
        value = IO::ByteFormat::LittleEndian.decode(UInt32, buf)
        @swapped ? value.byte_swap : value
      end
    end

    # -------------------------------------------------------------------------
    # PcapWriter - writes packets to a PCAP file
    # -------------------------------------------------------------------------

    # Creates new PCAP capture files. Writes the global header on
    # initialization, then individual packets as they come in.
    #
    # ```
    # writer = Filament::Capture::PcapWriter.new("output.pcap")
    # writer.write_packet(packet_bytes, Time.utc)
    # writer.close
    # ```
    class PcapWriter
      # The global header we wrote to the file
      getter header : PcapHeader

      # How many packets we've written so far
      getter packets_written : UInt64

      @io : IO
      @owns_io : Bool

      # Opens a new PCAP file for writing. Creates the file and writes
      # the global header immediately.
      def self.new(path : String, link_type : UInt32 = LINKTYPE_ETHERNET, snaplen : UInt32 = 65535_u32) : PcapWriter
        io = File.open(path, "wb")
        header = PcapHeader.default(link_type, snaplen)
        new(io, header, owns_io: true)
      end

      # Opens a PCAP file for writing, yields writer to block, and guarantees closure
      def self.open(path : String, link_type : UInt32 = LINKTYPE_ETHERNET, snaplen : UInt32 = 65535_u32, &block : PcapWriter ->)
        writer = new(path, link_type, snaplen)
        begin
          yield writer
        ensure
          writer.close
        end
      end

      # Creates a writer from an existing IO and header. Writes the
      # global header to the IO immediately.
      def initialize(@io : IO, @header : PcapHeader, @owns_io : Bool = false)
        @packets_written = 0_u64
        write_global_header
      end

      # Writes a single packet to the file. The data is the raw packet
      # bytes (starting with the link-layer header), and timestamp is
      # when the packet was captured.
      #
      # If the data is longer than the snap length, it gets truncated
      # in the file but the original length is preserved in the header.
      def write_packet(data : Bytes, timestamp : Time, original_length : UInt32? = nil)
        orig_len = original_length || data.size.to_u32
        incl_len = Math.min(data.size.to_u32, @header.snaplen)

        # Convert timestamp to seconds + microseconds
        unix_seconds = timestamp.to_unix.to_u32
        # Extract the sub-second microseconds from the timestamp
        usec = (timestamp.to_unix_ms % 1000 * 1000 + timestamp.nanosecond // 1000 % 1000).to_u32

        # Write the 16-byte packet header
        write_u32(unix_seconds)
        write_u32(usec)
        write_u32(incl_len)
        write_u32(orig_len)

        # Write the packet data (possibly truncated)
        @io.write(data[0, incl_len])

        @packets_written += 1
      end

      # Writes a RawPacket struct to the file. Convenience wrapper around
      # the bytes-based write_packet method.
      def write_raw_packet(packet : RawPacket)
        write_packet(packet.data, packet.timestamp, packet.original_length)
      end

      # Flushes the underlying IO buffer to disk. Call this periodically
      # during long captures so you don't lose data on a crash.
      def flush
        @io.flush
      end

      # Closes the writer and flushes all pending data.
      def close
        flush
        @io.close if @owns_io
      end

      # -----------------------------------------------------------------------
      # Private helpers
      # -----------------------------------------------------------------------

      # Writes the 24-byte global header to the file. Called once during
      # initialization.
      private def write_global_header
        write_u32(@header.magic_number)
        write_u16(@header.version_major)
        write_u16(@header.version_minor)
        write_i32(@header.thiszone)
        write_u32(@header.sigfigs)
        write_u32(@header.snaplen)
        write_u32(@header.link_type)
      end

      # Writes a 32-bit unsigned integer in little-endian byte order.
      # PCAP files written by this tool always use native (little-endian
      # on x86/ARM) byte order.
      private def write_u32(value : UInt32)
        buf = Bytes.new(4)
        IO::ByteFormat::LittleEndian.encode(value, buf)
        @io.write(buf)
      end

      # Writes a 16-bit unsigned integer in little-endian byte order.
      private def write_u16(value : UInt16)
        buf = Bytes.new(2)
        IO::ByteFormat::LittleEndian.encode(value, buf)
        @io.write(buf)
      end

      # Writes a 32-bit signed integer in little-endian byte order.
      private def write_i32(value : Int32)
        write_u32(value.to_u32!)
      end
    end
  end
end
