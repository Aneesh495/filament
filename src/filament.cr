# =============================================================================
# filament.cr - Core entry point and module definitions
# =============================================================================
#
# Filament is a programmable network protocol dissector, flow correlation,
# and traffic forensics engine built for high-throughput packet analysis.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./filament/capture/packet"
require "./filament/capture/pcap"
require "./filament/capture/pcapng"
require "./filament/capture/ring_buffer"
require "./filament/capture/bpf"
require "./filament/capture/mmap_reader"
require "./filament/capture/live"

module Filament
  VERSION = "0.1.0"
end
