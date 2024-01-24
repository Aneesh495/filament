# =============================================================================
# runner.cr - Filament Command Line Interface (CLI) runner
# =============================================================================
#
# Implements the command-line entrypoint for filament:
#   - Option parsing for live and offline capture modes
#   - FQL filter expression evaluation
#   - Terminal output with protocol colorization and hex dump rendering
#   - Graceful signal handling on SIGINT (Ctrl+C) to print summary tables
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "option_parser"
require "../engine"

module Filament
  module Cli
    class Runner
      def self.run(args : Array(String) = ARGV) : Int32
        pcap_file : String? = nil
        interface : String? = nil
        filter_expr : String? = nil
        max_packets : UInt64? = nil
        show_hexdump = false
        show_stats = false
        json_output = false
        list_ifaces = false

        parser = OptionParser.parse(args) do |opts|
          opts.banner = "Usage: filament [options]"

          opts.on("-r FILE", "--read FILE", "Read packet trace from PCAP or PCAPng file") do |f|
            pcap_file = f
          end

          opts.on("-i DEV", "--interface DEV", "Capture live traffic from network interface") do |dev|
            interface = dev
          end

          opts.on("-Y EXPR", "--filter EXPR", "Apply FQL (Filament Query Language) filter expression") do |expr|
            filter_expr = expr
          end

          opts.on("-c COUNT", "--count COUNT", "Stop after reading COUNT packets") do |cnt|
            max_packets = cnt.to_u64?
          end

          opts.on("-x", "--hexdump", "Display hexadecimal and ASCII dump for matched packets") do
            show_hexdump = true
          end

          opts.on("-s", "--stats", "Display statistical summary report upon completion") do
            show_stats = true
          end

          opts.on("-j", "--json", "Output packets as newline-delimited JSON") do
            json_output = true
          end

          opts.on("-l", "--list-interfaces", "List available network interfaces for live capture") do
            list_ifaces = true
          end

          opts.on("-v", "--version", "Display version information") do
            puts "filament #{Filament::VERSION}"
            exit 0
          end

          opts.on("-h", "--help", "Show this help guide") do
            puts opts
            exit 0
          end
        end

        if list_ifaces
          puts "Available Network Interfaces:"
          puts "-" * 40
          Capture::LiveCapture.available_interfaces.each do |iface|
            flags = [] of String
            flags << "UP" if iface.up?
            flags << "RUNNING" if iface.running?
            flags << "LOOPBACK" if iface.loopback?
            flag_str = flags.empty? ? "" : " [#{flags.join(", ")}]"
            puts sprintf("  %-16s %s%s", iface.name, iface.description || "", flag_str)
          end
          return 0
        end

        unless pcap_file || interface
          puts "filament: no capture source specified. Use -r FILE to read a PCAP or -i DEV for live capture."
          puts "Run 'filament --help' for usage guide."
          return 1
        end

        engine = Engine.new(filter_expr: filter_expr)

        # Setup Ctrl+C trap to flush stats cleanly
        interrupted = false
        Signal::INT.trap do
          if interrupted
            exit 130
          end
          interrupted = true
          puts "\nCapture interrupted by user."
          if show_stats
            engine.print_summary_report(STDOUT)
          end
          exit 0
        end

        # Packet processing callback
        on_packet = ->(decoded : Dissect::DecodedPacket) {
          if json_output
            # Emit compact JSON record
            puts %({"id":#{decoded.packet_id},"highest_proto":"#{decoded.highest_protocol}","len":#{decoded.raw.captured_length}})
          else
            summary_str = decoded.summary
            top_proto = decoded.highest_protocol
            colorized = Util::Ansi.colorize_protocol(top_proto, summary_str)
            puts colorized

            if show_hexdump
              puts decoded.hex_dump
            end
          end
        }

        if pcap_path = pcap_file
          unless File.exists?(pcap_path)
            STDERR.puts "filament: error: file '#{pcap_path}' not found."
            return 1
          end

          engine.run_pcap(pcap_path, max_packets: max_packets, &on_packet)
        elsif iface_name = interface
          live = Capture::LiveCapture.new(iface_name)
          count = 0_u64
          live.each do |raw_pkt|
            engine.process_raw_packet(raw_pkt, &on_packet)
            count += 1
            if (limit = max_packets) && count >= limit
              break
            end
          end
        end

        if show_stats
          engine.print_summary_report(STDOUT)
        end

        0
      end
    end
  end
end
