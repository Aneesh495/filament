# =============================================================================
# tcp_state.cr - RFC 793 / RFC 9293 TCP connection state machine
# =============================================================================
#
# Implements the canonical 11-state TCP finite state machine, tracking both
# endpoints through connection establishment (three-way handshake), steady-state
# data exchange, active/passive teardown, and reset termination.
#
# States:
#   CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED,
#   FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./key"

module Filament
  module Flow
    enum TcpState
      Closed
      Listen
      SynSent
      SynReceived
      Established
      FinWait1
      FinWait2
      CloseWait
      Closing
      LastAck
      TimeWait

      # Returns true if the TCP connection is fully open and usable for data
      def open? : Bool
        self == Established
      end

      # Returns true if the TCP connection has terminated or is terminating
      def closing? : Bool
        self.in?(FinWait1, FinWait2, CloseWait, Closing, LastAck, TimeWait, Closed)
      end
    end

    # Finite State Machine tracking a bidirectional TCP conversation
    class TcpConnectionTracker
      getter state : TcpState
      getter client_state : TcpState
      getter server_state : TcpState

      def initialize
        @state = TcpState::Closed
        @client_state = TcpState::Closed
        @server_state = TcpState::Closed
      end

      # Updates state machine given a TCP segment in either forward (client->server)
      # or reverse (server->client) direction
      def process_segment(
        direction : FlowDirection,
        syn : Bool,
        ack : Bool,
        fin : Bool,
        rst : Bool,
      ) : TcpState
        # Immediate reset
        if rst
          @state = TcpState::Closed
          @client_state = TcpState::Closed
          @server_state = TcpState::Closed
          return @state
        end

        case @state
        when TcpState::Closed
          if direction == FlowDirection::Forward && syn && !ack
            @client_state = TcpState::SynSent
            @server_state = TcpState::Listen
            @state = TcpState::SynSent
          end
        when TcpState::SynSent
          if direction == FlowDirection::Reverse && syn && ack
            @server_state = TcpState::SynReceived
            @state = TcpState::SynReceived
          elsif direction == FlowDirection::Reverse && syn && !ack
            # Simultaneous open
            @server_state = TcpState::SynReceived
            @state = TcpState::SynReceived
          end
        when TcpState::SynReceived
          if direction == FlowDirection::Forward && ack
            @client_state = TcpState::Established
            @server_state = TcpState::Established
            @state = TcpState::Established
          end
        when TcpState::Established
          if fin
            if direction == FlowDirection::Forward
              @client_state = TcpState::FinWait1
              @server_state = TcpState::CloseWait
              @state = TcpState::FinWait1
            else
              @server_state = TcpState::FinWait1
              @client_state = TcpState::CloseWait
              @state = TcpState::CloseWait
            end
          end
        when TcpState::FinWait1
          if direction == FlowDirection::Reverse
            if ack && !fin
              @client_state = TcpState::FinWait2
              @state = TcpState::FinWait2
            elsif fin && !ack
              # Simultaneous close
              @state = TcpState::Closing
            elsif fin && ack
              @state = TcpState::TimeWait
            end
          end
        when TcpState::FinWait2
          if direction == FlowDirection::Reverse && fin
            @state = TcpState::TimeWait
          end
        when TcpState::CloseWait
          if direction == FlowDirection::Forward && fin
            @client_state = TcpState::LastAck
            @state = TcpState::LastAck
          end
        when TcpState::Closing
          if ack
            @state = TcpState::TimeWait
          end
        when TcpState::LastAck
          if ack
            @state = TcpState::Closed
            @client_state = TcpState::Closed
            @server_state = TcpState::Closed
          end
        when TcpState::TimeWait
          # Remains in TimeWait until timeout or recycling
        end

        @state
      end
    end
  end
end
