# =============================================================================
# packet.cr - Core packet representation types
# =============================================================================
#
# This file defines the fundamental data structures that every other part of
# filament uses to represent captured network packets. Think of these as the
# "common currency" of the dissector: no matter where a packet came from
# (pcap file, pcapng file, live capture, generated test data), it ends up
# as a RawPacket struct that flows through the rest of the pipeline.
#
# We deliberately keep these types simple and cheap to copy. RawPacket is a
# struct (value type) because we'll be creating millions of them in a typical
# analysis session. The Bytes inside it point to the actual packet data
# buffer, so copying a RawPacket is just copying a fat pointer + a few scalars.
#
# Author: filament contributors
# License: MIT
# =============================================================================

module Filament
  module Capture
    # -------------------------------------------------------------------------
    # LinkType - identifies the link-layer encapsulation
    # -------------------------------------------------------------------------

    # Enumerates the link-layer header types we know how to handle.
    # Each value corresponds to a LINKTYPE_* constant from tcpdump.org.
    #
    # The link type tells our dissector what to expect at the very start
    # of the packet data. For Ethernet, that's a 14-byte Ethernet II header.
    # For Raw, it's an IP header with no link-layer wrapper. For Linux SLL,
    # it's the 16-byte Linux "cooked" header that tcpdump uses when
    # capturing on the "any" pseudo-interface.
    enum LinkType : UInt32
      # BSD loopback encapsulation. The first 4 bytes are a protocol
      # family identifier (AF_INET, AF_INET6, etc.)
      Null = 0

      # Standard Ethernet II frames. The first 14 bytes are:
      # dst_mac (6) + src_mac (6) + ethertype (2)
      Ethernet = 1

      # Raw IP packets with no link-layer header. The first byte's
      # upper nibble tells you whether it's IPv4 (4) or IPv6 (6).
      Raw = 101

      # Linux "cooked" capture format. Used when capturing on the
      # "any" interface or on interfaces that don't have a standard
      # link-layer header (like PPP, tunnel interfaces, etc.)
      LinuxSll = 113

      # Linux "cooked" capture format version 2. Fixes some issues
      # with the original format, mainly around VLAN handling.
      LinuxSll2 = 276

      # Returns a human-readable name for this link type, useful for
      # display in the UI or log messages.
      def description : String
        case self
        in .null?        then "BSD Loopback"
        in .ethernet?    then "Ethernet"
        in .raw?         then "Raw IP"
        in .linux_sll?   then "Linux Cooked Capture"
        in .linux_sll2?  then "Linux Cooked Capture v2"
        end
      end

      # Returns the typical header length for this link type. This is
      # how many bytes we need to skip to get to the network layer.
      # Returns 0 for Raw since there's no link-layer header at all.
      def header_length : Int32
        case self
        in .null?        then 4
        in .ethernet?    then 14
        in .raw?         then 0
        in .linux_sll?   then 16
        in .linux_sll2?  then 20
        end
      end

      # Tries to convert an integer to a LinkType. Returns nil if the
      # value doesn't match any known type, rather than raising, so
      # callers can handle unknown types gracefully.
      def self.from_value?(value : UInt32) : LinkType?
        case value
        when   0 then Null
        when   1 then Ethernet
        when 101 then Raw
        when 113 then LinuxSll
        when 276 then LinuxSll2
        else          nil
        end
      end

      # Like from_value? but raises on unknown types. Used when we
      # know the value should be valid (e.g., reading from a header
      # we've already validated).
      def self.from_value(value : UInt32) : LinkType
        from_value?(value) || raise PcapError.new(
          "Unknown link type: #{value}. " \
          "Supported types: Null (0), Ethernet (1), Raw (101), " \
          "LinuxSLL (113), LinuxSLL2 (276)."
        )
      end
    end

    # -------------------------------------------------------------------------
    # CaptureSource - where did this packet come from?
    # -------------------------------------------------------------------------

    # Tracks the origin of a packet so downstream code can make decisions
    # based on whether we're working with real traffic or test data.
    enum CaptureSource
      # Packet was read from a PCAP or PCAPng file
      File

      # Packet was captured live from a network interface
      Live

      # Packet was programmatically generated (for testing, fuzzing, etc.)
      Generated
    end

    # -------------------------------------------------------------------------
    # PacketMetadata - extra context about a packet
    # -------------------------------------------------------------------------

    # Carries additional context about a packet that doesn't fit in the
    # core RawPacket struct. This is optional metadata that's nice to have
    # for display purposes but isn't needed for protocol dissection.
    #
    # We keep this separate from RawPacket to avoid bloating the struct
    # that gets copied around millions of times. Only packets that need
    # annotation get a metadata object allocated for them.
    struct PacketMetadata
      # Name of the file this packet came from (nil for live captures)
      getter filename : String?

      # Sequential packet number within the capture (1-based, because
      # that's what Wireshark uses and everyone's used to it)
      getter packet_number : UInt64

      # Optional comment attached to the packet (supported in pcapng)
      getter comment : String?

      # Where this packet came from
      getter source : CaptureSource

      # Optional verdict or annotation added during analysis
      property annotation : String?

      def initialize(
        @filename : String? = nil,
        @packet_number : UInt64 = 0_u64,
        @comment : String? = nil,
        @source : CaptureSource = CaptureSource::File,
        @annotation : String? = nil
      )
      end

      # Returns a compact string representation for log output.
      def to_s(io : IO) : Nil
        io << "Packet ##{@packet_number}"
        if fname = @filename
          io << " from #{fname}"
        end
        if cmt = @comment
          io << " [#{cmt}]"
        end
      end
    end

    # -------------------------------------------------------------------------
    # RawPacket - the core packet representation
    # -------------------------------------------------------------------------

    # Represents a single captured network packet with all the information
    # we need to dissect and analyze it. This is a value type (struct) for
    # performance, since we'll create millions of these during a typical
    # analysis run.
    #
    # ```
    # packet = RawPacket.new(
    #   data: raw_bytes,
    #   timestamp: Time.utc,
    #   original_length: 1514_u32,
    #   capture_length: 1514_u32,
    #   interface_id: 0_u32,
    #   link_type: LinkType::Ethernet
    # )
    # puts packet.truncated? # => false
    # ```
    struct RawPacket
      # The raw packet bytes, starting with the link-layer header. This
      # slice may be shorter than the original packet if snapping occurred.
      getter data : Bytes

      # When the packet was captured. For file-based captures this comes
      # from the packet header timestamp. For live captures it's set by
      # the capture engine.
      getter timestamp : Time

      # The original length of the packet on the wire, before any
      # truncation due to snap length.
      getter original_length : UInt32

      # How many bytes were actually captured. Equal to data.size, but
      # stored explicitly for clarity and to match the PCAP format.
      getter capture_length : UInt32

      # Alias for captured_length
      def captured_length : UInt32
        @capture_length
      end

      # Which interface captured this packet. For classic PCAP this is
      # always 0 (there's only one interface). For pcapng, each interface
      # gets a sequential ID.
      getter interface_id : UInt32

      # The link-layer header type. Determines how to parse the first
      # bytes of the packet data.
      getter link_type : LinkType

      def initialize(
        @data : Bytes,
        @timestamp : Time,
        @original_length : UInt32,
        @capture_length : UInt32,
        @interface_id : UInt32 = 0_u32,
        @link_type : LinkType = LinkType::Ethernet
      )
      end

      # Convenience constructor allowing captured_length keyword
      def self.new(
        data : Bytes,
        timestamp : Time,
        original_length : UInt32,
        captured_length : UInt32,
        link_type : LinkType = LinkType::Ethernet,
        interface_id : UInt32 = 0_u32
      )
        new(data, timestamp, original_length, captured_length, interface_id, link_type)
      end

      # Was this packet truncated? Returns true if the captured data is
      # shorter than what was actually on the wire.
      def truncated? : Bool
        @capture_length < @original_length
      end

      # Was the entire packet captured without truncation?
      def full_capture? : Bool
        @capture_length >= @original_length
      end

      # Returns the timestamp as microseconds since the Unix epoch.
      # Useful for high-precision timing calculations.
      def timestamp_usec : Int64
        @timestamp.to_unix_ms * 1000 + @timestamp.nanosecond // 1000 % 1000
      end

      # Returns the timestamp as nanoseconds since the Unix epoch.
      # Maximum precision available from the capture.
      def timestamp_nsec : Int64
        @timestamp.to_unix * 1_000_000_000_i64 + @timestamp.nanosecond
      end

      # How many bytes of the original packet are missing due to
      # snap length truncation? Returns 0 if the full packet was captured.
      def bytes_missing : UInt32
        if truncated?
          @original_length - @capture_length
        else
          0_u32
        end
      end

      # Returns the packet data starting after the link-layer header.
      # This gives you the network layer (usually IP) payload directly.
      # Returns nil if the packet is too short to contain even a
      # complete link-layer header.
      def network_payload : Bytes?
        header_len = @link_type.header_length
        if @data.size > header_len
          @data[header_len..]
        else
          nil
        end
      end

      # Returns a concise summary string for logging and debugging.
      def to_s(io : IO) : Nil
        io << "RawPacket("
        io << "#{@capture_length}/#{@original_length} bytes, "
        io << "#{@link_type.description}, "
        io << "if=#{@interface_id}, "
        io << @timestamp.to_s("%H:%M:%S.%6N")
        io << ")"
      end
    end
  end
end
