# =============================================================================
# ansi.cr - ANSI colorization and protocol-specific terminal palettes
# =============================================================================
#
# Provides color themes for syntax highlighting packet captures in terminals,
# matching Wireshark's standard color filter rules.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "../dissect/dissector"

module Filament
  module Util
    module Ansi
      RESET     = "\e[0m"
      BOLD      = "\e[1m"
      DIM       = "\e[2m"
      UNDERLINE = "\e[4m"

      # Foreground colors
      BLACK   = "\e[30m"
      RED     = "\e[31m"
      GREEN   = "\e[32m"
      YELLOW  = "\e[33m"
      BLUE    = "\e[34m"
      MAGENTA = "\e[35m"
      CYAN    = "\e[36m"
      WHITE   = "\e[37m"

      # Bright foreground colors
      BRIGHT_BLACK   = "\e[90m"
      BRIGHT_RED     = "\e[91m"
      BRIGHT_GREEN   = "\e[92m"
      BRIGHT_YELLOW  = "\e[93m"
      BRIGHT_BLUE    = "\e[94m"
      BRIGHT_MAGENTA = "\e[95m"
      BRIGHT_CYAN    = "\e[96m"
      BRIGHT_WHITE   = "\e[97m"

      # Returns colorized string matching protocol palette
      def self.colorize_protocol(proto : Dissect::Protocol, text : String) : String
        case proto
        when Dissect::Protocol::Ethernet  then "#{CYAN}#{text}#{RESET}"
        when Dissect::Protocol::Arp       then "#{YELLOW}#{text}#{RESET}"
        when Dissect::Protocol::IPv4      then "#{BLUE}#{text}#{RESET}"
        when Dissect::Protocol::IPv6      then "#{BRIGHT_BLUE}#{text}#{RESET}"
        when Dissect::Protocol::Icmp,
             Dissect::Protocol::Icmpv6    then "#{BRIGHT_YELLOW}#{text}#{RESET}"
        when Dissect::Protocol::Tcp       then "#{GREEN}#{text}#{RESET}"
        when Dissect::Protocol::Udp       then "#{BRIGHT_CYAN}#{text}#{RESET}"
        when Dissect::Protocol::Dns       then "#{MAGENTA}#{text}#{RESET}"
        when Dissect::Protocol::Http      then "#{BRIGHT_GREEN}#{text}#{RESET}"
        when Dissect::Protocol::Tls       then "#{BRIGHT_MAGENTA}#{text}#{RESET}"
        when Dissect::Protocol::Dhcp      then "#{YELLOW}#{text}#{RESET}"
        when Dissect::Protocol::Ntp       then "#{CYAN}#{text}#{RESET}"
        when Dissect::Protocol::WebSocket then "#{BRIGHT_WHITE}#{text}#{RESET}"
        else "#{WHITE}#{text}#{RESET}"
        end
      end

      # Formats error messages in red
      def self.error(msg : String) : String
        "#{BRIGHT_RED}#{msg}#{RESET}"
      end

      # Formats warnings in yellow
      def self.warn(msg : String) : String
        "#{BRIGHT_YELLOW}#{msg}#{RESET}"
      end

      # Formats success messages in green
      def self.success(msg : String) : String
        "#{BRIGHT_GREEN}#{msg}#{RESET}"
      end

      # Strips ANSI escape sequences from text for clean length calculation
      def self.strip(text : String) : String
        text.gsub(/\e\[[0-9;]*m/, "")
      end
    end
  end
end
