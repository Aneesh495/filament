# =============================================================================
# filament.cr - Core library entry point
# =============================================================================
#
# Filament is a programmable network protocol dissector, flow correlation,
# and traffic forensics engine built for high-throughput packet analysis.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./filament/engine"
require "./filament/cli/runner"

module Filament
  VERSION = "0.1.0"
end
