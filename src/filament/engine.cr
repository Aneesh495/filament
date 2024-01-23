# =============================================================================
# engine.cr - Core pipeline orchestrator and capture session coordinator
# =============================================================================
#
# Unites all architectural subsystems:
#   Capture Layer -> Dissection Engine -> Filter VM -> Flow Table -> Analytics
#
# Manages the streaming ingestion of packets from files (PCAP, PCAPng, mmap)
# or live network interfaces, applies compile-once FQL filters, maintains
# bidirectional flow state, and populates statistical aggregation matrices.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./capture/packet"
require "./capture/pcap"
require "./capture/pcapng"
require "./capture/mmap_reader"
require "./capture/live"
require "./dissect/dissector"
require "./dissect/decoded_packet"
require "./dissect/layer2/ethernet"
require "./dissect/layer2/arp"
require "./dissect/layer2/sll"
require "./dissect/layer2/ppp"
require "./dissect/layer3/ipv4"
require "./dissect/layer3/ipv4_reassembler"
require "./dissect/layer3/ipv6"
require "./dissect/layer3/icmp"
require "./dissect/layer3/icmpv6"
require "./dissect/layer4/udp"
require "./dissect/layer4/tcp"
require "./dissect/layer7/dns"
require "./dissect/layer7/http"
require "./dissect/layer7/tls"
require "./dissect/layer7/dhcp"
require "./dissect/layer7/ntp"
require "./dissect/layer7/websocket"
require "./flow/key"
require "./flow/record"
require "./flow/table"
require "./filter/parser"
require "./filter/compiler"
require "./filter/vm"
require "./stats/hierarchy"
require "./stats/endpoints"
require "./stats/conversations"
require "./stats/io_rate"
require "./stats/latency"
require "./util/ansi"
require "./util/format"

module Filament
  class Engine
    getter hierarchy : Stats::ProtocolHierarchy
    getter endpoints : Stats::EndpointsTable
    getter conversations : Stats::ConversationsTable
    getter io_rate : Stats::IoRateAnalyzer
    getter latency : Stats::LatencyAnalyzer
    getter flow_table : Flow::FlowTable

    getter packets_processed : UInt64
    getter packets_matched : UInt64
    getter bytes_processed : UInt64
    getter start_time : Time?
    getter filter_expr : String?

    @compiled_filter : Filter::CompiledFilter

    def initialize(@filter_expr : String? = nil)
      @hierarchy = Stats::ProtocolHierarchy.new
      @endpoints = Stats::EndpointsTable.new
      @conversations = Stats::ConversationsTable.new
      @io_rate = Stats::IoRateAnalyzer.new
      @latency = Stats::LatencyAnalyzer.new
      @flow_table = Flow::FlowTable.new

      @packets_processed = 0_u64
      @packets_matched = 0_u64
      @bytes_processed = 0_u64
      @start_time = nil

      # Register all known protocol dissectors into global registry
      register_dissectors

      # Compile FQL filter if provided
      @compiled_filter = if f = @filter_expr
                           ast = Filter::Parser.parse(f)
                           Filter::Compiler.compile(ast)
                         else
                           Filter::CompiledFilter.accept_all
                         end
    end

    # Registers dissectors across layers
    private def register_dissectors : Nil
      reg = Dissect::DissectorRegistry.instance
      reg.register(Dissect::Layer2::EthernetDissector.new)
      reg.register(Dissect::Layer2::ArpDissector.new)
      reg.register(Dissect::Layer2::SllDissector.new)
      reg.register(Dissect::Layer2::PppDissector.new)
      reg.register(Dissect::Layer3::IPv4Dissector.new)
      reg.register(Dissect::Layer3::IPv6Dissector.new)
      reg.register(Dissect::Layer3::IcmpDissector.new)
      reg.register(Dissect::Layer3::Icmpv6Dissector.new)
      reg.register(Dissect::Layer4::UdpDissector.new)
      reg.register(Dissect::Layer4::TcpDissector.new)
      reg.register(Dissect::Layer7::DnsDissector.new)
      reg.register(Dissect::Layer7::HttpDissector.new)
      reg.register(Dissect::Layer7::TlsDissector.new)
      reg.register(Dissect::Layer7::DhcpDissector.new)
      reg.register(Dissect::Layer7::NtpDissector.new)
      reg.register(Dissect::Layer7::WebSocketDissector.new)
    end

    # Processes a raw packet through the complete pipeline
    def process_raw_packet(packet : Capture::RawPacket, &on_match : Dissect::DecodedPacket ->) : Nil
      @start_time ||= packet.timestamp
      @packets_processed += 1_u64
      @bytes_processed += packet.captured_length.to_u64

      # 1. Dissect layers
      decoded = Dissect::DecodedPacket.decode(packet, @packets_processed)

      # 2. Evaluate FQL filter
      if Filter::FilterVM.match?(@compiled_filter, decoded)
        @packets_matched += 1_u64

        # 3. Update flow table and analytical statistics
        @flow_table.process(decoded)
        @hierarchy.process(decoded)
        @endpoints.process(decoded)
        @conversations.process(decoded)
        @io_rate.process(decoded)
        @latency.process(decoded)

        # 4. Notify packet listener
        yield decoded
      end
    end

    # Runs engine on an open PCAP file
    def run_pcap(path : String, max_packets : UInt64? = nil, &block : Dissect::DecodedPacket ->) : Nil
      Capture::PcapReader.open(path) do |reader|
        reader.each do |raw_pkt|
          process_raw_packet(raw_pkt, &block)
          break if max_packets && @packets_processed >= max_packets
        end
      end
    end

    # Prints consolidated forensic report
    def print_summary_report(io : IO) : Nil
      io << "\n"
      io << "=" * 80 << "\n"
      io << "                 FILAMENT TRAFFIC FORENSICS REPORT\n"
      io << "=" * 80 << "\n"
      io << sprintf("Packets Processed: %10d | Packets Matched: %10d\n", @packets_processed, @packets_matched)
      io << sprintf("Total Data Volume: %10s | Active Flows:    %10d\n",
        Util::Format.human_bytes(@bytes_processed), @flow_table.size)
      io << "-" * 80 << "\n\n"

      io << "1. PROTOCOL HIERARCHY\n"
      @hierarchy.to_s(io)
      io << "\n"

      io << "2. TOP ENDPOINTS (BY DATA VOLUME)\n"
      @endpoints.to_s(io)
      io << "\n"

      io << "3. TOP CONVERSATIONS\n"
      @conversations.to_s(io)
      io << "\n"

      io << "4. LATENCY DISTRIBUTION\n"
      @latency.to_s(io)
      io << "\n"

      io << "5. THROUGHPUT TIME DISTRIBUTION\n"
      io << @io_rate.ascii_chart << "\n"
      io << "=" * 80 << "\n"
    end
  end
end
