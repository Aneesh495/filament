# =============================================================================
# live.cr - Native libpcap FFI bindings and real-time capture engine
# =============================================================================
#
# Provides an idiomatic Crystal wrapper around system libpcap for real-time
# wire packet acquisition on Linux (PF_PACKET/AF_PACKET) and macOS (BPF).
#
# libpcap is the de facto standard low-level network traffic capture API.
# It handles promiscuous mode, memory-mapped packet rings, hardware timestamping,
# and in-kernel BPF filtering.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./packet"

module Filament
  module Capture
    # Raw C library bindings to system libpcap
    @[Link("pcap")]
    lib LibPcap
      # Opaque handle types
      type PcapT = Void*
      type PcapDumperT = Void*

      # libpcap sockaddr structure
      struct SockAddr
        sa_len : UInt8
        sa_family : UInt8
        sa_data : StaticArray(UInt8, 14)
      end

      # Interface address node
      struct PcapAddr
        next : PcapAddr*
        addr : SockAddr*
        netmask : SockAddr*
        broadaddr : SockAddr*
        dstaddr : SockAddr*
      end

      # Network device descriptor node
      struct PcapIf
        next : PcapIf*
        name : LibC::Char*
        description : LibC::Char*
        addresses : PcapAddr*
        flags : UInt32
      end

      # Timeval structure matching system architecture
      struct TimeVal
        tv_sec : LibC::TimeT
        tv_usec : LibC::SusecondsT
      end

      # Packet header returned by pcap_next_ex
      struct PcapPkthdr
        ts : TimeVal
        caplen : UInt32
        len : UInt32
      end

      # Compiled BPF filter program
      struct BpfProgramRaw
        bf_len : UInt32
        bf_insns : Void*
      end

      # Statistics structure
      struct PcapStat
        ps_recv : UInt32
        ps_drop : UInt32
        ps_ifdrop : UInt32
      end

      # Function prototypes
      fun pcap_lookupdev(errbuf : LibC::Char*) : LibC::Char*
      fun pcap_findalldevs(alldevsp : PcapIf**, errbuf : LibC::Char*) : LibC::Int
      fun pcap_freealldevs(alldevs : PcapIf*) : Void
      fun pcap_open_live(device : LibC::Char*, snaplen : LibC::Int, promisc : LibC::Int, to_ms : LibC::Int, errbuf : LibC::Char*) : PcapT
      fun pcap_open_offline(fname : LibC::Char*, errbuf : LibC::Char*) : PcapT
      fun pcap_close(p : PcapT) : Void
      fun pcap_next_ex(p : PcapT, pkt_header : PcapPkthdr**, pkt_data : UInt8**) : LibC::Int
      fun pcap_datalink(p : PcapT) : LibC::Int
      fun pcap_compile(p : PcapT, fp : BpfProgramRaw*, str : LibC::Char*, optimize : LibC::Int, netmask : UInt32) : LibC::Int
      fun pcap_setfilter(p : PcapT, fp : BpfProgramRaw*) : LibC::Int
      fun pcap_freecode(fp : BpfProgramRaw*) : Void
      fun pcap_geterr(p : PcapT) : LibC::Char*
      fun pcap_stats(p : PcapT, ps : PcapStat*) : LibC::Int
      fun pcap_breakloop(p : PcapT) : Void
    end

    # High-level representation of an OS network interface
    struct NetworkInterfaceInfo
      getter name : String
      getter description : String?
      getter? loopback : Bool
      getter? up : Bool
      getter? running : Bool

      def initialize(
        @name : String,
        @description : String? = nil,
        @loopback : Bool = false,
        @up : Bool = false,
        @running : Bool = false,
      )
      end
    end

    # Interface statistics snapshot
    struct CaptureStatistics
      getter received : UInt32
      getter dropped_by_driver : UInt32
      getter dropped_by_interface : UInt32

      def initialize(@received : UInt32, @dropped_by_driver : UInt32, @dropped_by_interface : UInt32)
      end
    end

    # Exception raised when libpcap operations fail
    class LiveCaptureError < Exception
    end

    # Real-time packet capture handle managing an active live interface
    class LiveCapture
      include Enumerable(RawPacket)

      getter device : String
      getter snap_len : Int32
      getter? promiscuous : Bool
      getter timeout_ms : Int32
      getter link_type : LinkType
      getter? active : Bool

      @handle : LibPcap::PcapT?
      @bpf_program : LibPcap::BpfProgramRaw

      # Discovers all capture-capable network interfaces present on the system
      def self.available_interfaces : Array(NetworkInterfaceInfo)
        errbuf = Bytes.new(256, 0_u8)
        devs_ptr = Pointer(LibPcap::PcapIf*).malloc(1)

        ret = LibPcap.pcap_findalldevs(devs_ptr, errbuf.to_unsafe.as(LibC::Char*))
        if ret != 0
          err_msg = String.new(errbuf.to_unsafe.as(LibC::Char*))
          raise LiveCaptureError.new("Failed to discover network interfaces: #{err_msg}")
        end

        result = [] of NetworkInterfaceInfo
        current = devs_ptr.value

        while current
          dev = current.value
          name = String.new(dev.name)
          desc = dev.description ? String.new(dev.description) : nil
          flags = dev.flags

          is_loopback = (flags & 0x00000001_u32) != 0_u32
          is_up = (flags & 0x00000002_u32) != 0_u32
          is_running = (flags & 0x00000004_u32) != 0_u32

          result << NetworkInterfaceInfo.new(
            name: name,
            description: desc,
            loopback: is_loopback,
            up: is_up,
            running: is_running
          )

          current = dev.next
        end

        LibPcap.pcap_freealldevs(devs_ptr.value)
        result
      end

      # Opens an interface for live promiscuous packet capture
      def initialize(
        @device : String,
        @snap_len : Int32 = 65535,
        @promiscuous : Bool = true,
        @timeout_ms : Int32 = 1000,
        filter : String? = nil,
      )
        @active = false
        @bpf_program = LibPcap::BpfProgramRaw.new
        errbuf = Bytes.new(256, 0_u8)

        handle = LibPcap.pcap_open_live(
          @device.to_unsafe,
          @snap_len,
          @promiscuous ? 1 : 0,
          @timeout_ms,
          errbuf.to_unsafe.as(LibC::Char*)
        )

        if handle.null?
          err_msg = String.new(errbuf.to_unsafe.as(LibC::Char*))
          raise LiveCaptureError.new("Unable to open device #{@device}: #{err_msg}")
        end

        @handle = handle
        @active = true

        # Query native datalink type
        dlt = LibPcap.pcap_datalink(handle)
        @link_type = LinkType.from_value?(dlt) || LinkType::Ethernet

        # Apply BPF filter if provided
        if filter && !filter.empty?
          set_filter(filter)
        end
      end

      # Compiles and attaches an in-kernel BPF filter expression
      def set_filter(expression : String) : Nil
        handle = @handle
        raise LiveCaptureError.new("Capture handle closed") unless handle && @active

        ret = LibPcap.pcap_compile(handle, pointerof(@bpf_program), expression.to_unsafe, 1, 0xFFFFFFFF_u32)
        if ret != 0
          err = String.new(LibPcap.pcap_geterr(handle))
          raise LiveCaptureError.new("Failed to compile BPF expression '#{expression}': #{err}")
        end

        ret = LibPcap.pcap_setfilter(handle, pointerof(@bpf_program))
        if ret != 0
          LibPcap.pcap_freecode(pointerof(@bpf_program))
          err = String.new(LibPcap.pcap_geterr(handle))
          raise LiveCaptureError.new("Failed to attach BPF filter to #{@device}: #{err}")
        end

        LibPcap.pcap_freecode(pointerof(@bpf_program))
      end

      # Fetches the next packet from the live buffer.
      # Returns nil if timeout expired without packets.
      def next_packet : RawPacket?
        handle = @handle
        return nil unless handle && @active

        hdr_ptr = uninitialized LibPcap::PcapPkthdr*
        data_ptr = uninitialized UInt8*

        ret = LibPcap.pcap_next_ex(handle, pointerof(hdr_ptr), pointerof(data_ptr))

        case ret
        when 1
          # Packet captured successfully
          hdr = hdr_ptr.value
          sec = hdr.ts.tv_sec.to_i64
          usec = hdr.ts.tv_usec.to_i32
          timestamp = Time.unix(sec) + Time::Span.new(nanoseconds: usec * 1_000)

          cap_len = hdr.caplen.to_i32
          orig_len = hdr.len

          # Copy packet bytes out of libpcap internal ring
          slice = Slice.new(data_ptr, cap_len)
          owned_bytes = Bytes.new(cap_len)
          slice.copy_to(owned_bytes)

          RawPacket.new(
            data: owned_bytes,
            timestamp: timestamp,
            original_length: orig_len,
            captured_length: hdr.caplen,
            link_type: @link_type,
            interface_id: 0_u32
          )
        when 0
          # Timeout expired
          nil
        when -1
          err = String.new(LibPcap.pcap_geterr(handle))
          raise LiveCaptureError.new("Error reading packet from #{@device}: #{err}")
        when -2
          # Loop broken via pcap_breakloop
          nil
        else
          nil
        end
      end

      # Iterates over packets continuously until stopped or broken
      def each(& : RawPacket ->)
        while @active
          pkt = next_packet
          yield pkt if pkt
        end
      end

      # Queries current kernel and driver drop statistics
      def statistics : CaptureStatistics
        handle = @handle
        raise LiveCaptureError.new("Capture handle closed") unless handle && @active

        stats = uninitialized LibPcap::PcapStat
        ret = LibPcap.pcap_stats(handle, pointerof(stats))
        if ret != 0
          err = String.new(LibPcap.pcap_geterr(handle))
          raise LiveCaptureError.new("Failed to retrieve capture statistics: #{err}")
        end

        CaptureStatistics.new(
          received: stats.ps_recv,
          dropped_by_driver: stats.ps_drop,
          dropped_by_interface: stats.ps_ifdrop
        )
      end

      # Stops capture and breaks active read loops
      def stop : Nil
        return unless @active
        if handle = @handle
          LibPcap.pcap_breakloop(handle)
        end
        @active = false
      end

      # Closes the libpcap descriptor and frees resources
      def close : Nil
        return unless @handle
        stop
        if handle = @handle
          LibPcap.pcap_close(handle)
          @handle = nil
        end
      end

      def finalize
        close
      end
    end
  end
end
