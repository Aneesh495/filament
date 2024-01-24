# =============================================================================
# main.cr - Standalone executable entry point for Filament CLI
# =============================================================================

require "../engine"
require "./runner"

exit Filament::Cli::Runner.run(ARGV)
