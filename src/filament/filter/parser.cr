# =============================================================================
# parser.cr - Pratt operator precedence parser for the FQL grammar
# =============================================================================
#
# Implements a top-down operator precedence (Pratt) parser for FQL.
# Correctly evaluates binding power across relational comparisons, boolean
# disjunctions, conjunctions, and negations without operator ambiguity.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./token"
require "./lexer"
require "./ast"

module Filament
  module Filter
    class ParserError < Exception
      getter line : Int32
      getter col : Int32

      def initialize(message : String, @line : Int32, @col : Int32)
        super("#{message} at #{@line}:#{@col}")
      end
    end

    enum Precedence
      Lowest
      Or          # or, ||
      And         # and, &&
      Equals      # ==, !=, ~=, in
      LessGreater # <, <=, >, >=
      Prefix      # not, !
    end

    class Parser
      @lexer : Lexer
      @cur_token : Token
      @peek_token : Token

      # Known protocol names that indicate a protocol presence check when standalone
      PROTOCOLS = [
        "eth", "ethernet", "vlan", "arp", "sll", "ppp",
        "ip", "ipv4", "ipv6", "icmp", "icmpv6",
        "tcp", "udp",
        "dns", "http", "tls", "ssl", "dhcp", "bootp", "ntp", "smtp", "websocket", "ws"
      ]

      def initialize(@lexer : Lexer)
        @cur_token = @lexer.next_token
        @peek_token = @lexer.next_token
      end

      def self.parse(input : String) : Expr?
        lexer = Lexer.new(input)
        parser = new(lexer)
        parser.parse_expression(Precedence::Lowest)
      end

      private def next_token : Nil
        @cur_token = @peek_token
        @peek_token = @lexer.next_token
      end

      private def cur_precedence : Precedence
        token_precedence(@cur_token.type)
      end

      private def peek_precedence : Precedence
        token_precedence(@peek_token.type)
      end

      private def token_precedence(type : TokenType) : Precedence
        case type
        when TokenType::Or          then Precedence::Or
        when TokenType::And         then Precedence::And
        when TokenType::Eq,
             TokenType::Ne,
             TokenType::Match,
             TokenType::In          then Precedence::Equals
        when TokenType::Lt,
             TokenType::Le,
             TokenType::Gt,
             TokenType::Ge          then Precedence::LessGreater
        else Precedence::Lowest
        end
      end

      # Main Pratt expression parsing driver
      def parse_expression(precedence : Precedence) : Expr?
        left = parse_prefix
        return nil unless left

        while @peek_token.type != TokenType::Eof && precedence < peek_precedence
          next_token
          left = parse_infix(left)
          return nil unless left
        end

        left
      end

      # Dispatches prefix parsing
      private def parse_prefix : Expr?
        case @cur_token.type
        when TokenType::Ident
          parse_ident_or_protocol
        when TokenType::Number
          parse_number
        when TokenType::String
          parse_string
        when TokenType::IpAddress
          IpLiteralExpr.new(@cur_token.text)
        when TokenType::Cidr
          CidrLiteralExpr.new(@cur_token.text)
        when TokenType::True
          BoolLiteralExpr.new(true)
        when TokenType::False
          BoolLiteralExpr.new(false)
        when TokenType::Not
          parse_unary
        when TokenType::LParen
          parse_grouped
        else
          raise ParserError.new("Unexpected token #{@cur_token.type} ('#{@cur_token.text}')", @cur_token.line, @cur_token.col)
        end
      end

      # Dispatches infix parsing
      private def parse_infix(left : Expr) : Expr?
        op_token = @cur_token
        prec = cur_precedence
        next_token

        right = parse_expression(prec)
        raise ParserError.new("Expected right-hand expression after #{op_token.type}", op_token.line, op_token.col) unless right

        BinaryOpExpr.new(left, op_token.type, right)
      end

      private def parse_ident_or_protocol : Expr
        text = @cur_token.text
        # If identifier has no dot and matches a protocol name, treat as protocol presence check
        if !text.includes?('.') && PROTOCOLS.includes?(text.downcase)
          ProtocolPresentExpr.new(text.downcase)
        else
          FieldAccessExpr.new(text)
        end
      end

      private def parse_number : Expr
        val = @cur_token.text.to_i64?(10) || @cur_token.text.to_i64?(16) || 0_i64
        NumberLiteralExpr.new(val)
      end

      private def parse_string : Expr
        StringLiteralExpr.new(@cur_token.text)
      end

      private def parse_unary : Expr
        op = @cur_token.type
        line = @cur_token.line
        col = @cur_token.col
        next_token

        sub = parse_expression(Precedence::Prefix)
        raise ParserError.new("Expected expression following #{op}", line, col) unless sub

        UnaryOpExpr.new(op, sub)
      end

      private def parse_grouped : Expr?
        next_token # skip '('
        expr = parse_expression(Precedence::Lowest)

        if @peek_token.type == TokenType::RParen
          next_token # consume ')'
          expr
        else
          raise ParserError.new("Unclosed parenthesis, expected ')'", @cur_token.line, @cur_token.col)
        end
      end
    end
  end
end
