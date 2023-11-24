# =============================================================================
# lexer.cr - Lexical scanner for the Filament Query Language (FQL)
# =============================================================================
#
# Scans an input FQL expression string into a sequence of typed Tokens.
# Handles whitespace, comments (#), escaped string literals, numbers in decimal
# and hexadecimal (0x...), IP addresses, and CIDR network blocks.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./token"

module Filament
  module Filter
    class LexerError < Exception
      getter line : Int32
      getter col : Int32

      def initialize(message : String, @line : Int32, @col : Int32)
        super("#{message} at #{@line}:#{@col}")
      end
    end

    class Lexer
      @input : String
      @pos : Int32
      @read_pos : Int32
      @ch : Char
      @line : Int32
      @col : Int32

      def initialize(@input : String)
        @pos = 0
        @read_pos = 0
        @ch = '\0'
        @line = 1
        @col = 0
        read_char
      end

      # Advances to next character in the input
      private def read_char : Nil
        if @read_pos >= @input.size
          @ch = '\0'
        else
          @ch = @input[@read_pos]
        end
        @pos = @read_pos
        @read_pos += 1
        @col += 1
      end

      # Peeks at the upcoming character without advancing
      private def peek_char : Char
        return '\0' if @read_pos >= @input.size
        @input[@read_pos]
      end

      # Skips whitespace and line comments starting with '#'
      private def skip_whitespace_and_comments : Nil
        loop do
          while @ch == ' ' || @ch == '\t' || @ch == '\r' || @ch == '\n'
            if @ch == '\n'
              @line += 1
              @col = 0
            end
            read_char
          end

          if @ch == '#'
            # Skip until end of line
            while @ch != '\n' && @ch != '\0'
              read_char
            end
            next
          end

          break
        end
      end

      # Produces the next token from the stream
      def next_token : Token
        skip_whitespace_and_comments

        token_line = @line
        token_col = @col

        token = case @ch
                when '\0'
                  Token.new(TokenType::Eof, "", token_line, token_col)
                when '('
                  read_char
                  Token.new(TokenType::LParen, "(", token_line, token_col)
                when ')'
                  read_char
                  Token.new(TokenType::RParen, ")", token_line, token_col)
                when ','
                  read_char
                  Token.new(TokenType::Comma, ",", token_line, token_col)
                when '='
                  if peek_char == '='
                    read_char
                    read_char
                    Token.new(TokenType::Eq, "==", token_line, token_col)
                  elsif peek_char == '~'
                    read_char
                    read_char
                    Token.new(TokenType::Match, "=~", token_line, token_col)
                  else
                    read_char
                    Token.new(TokenType::Eq, "==", token_line, token_col) # Lenient single = as ==
                  end
                when '!'
                  if peek_char == '='
                    read_char
                    read_char
                    Token.new(TokenType::Ne, "!=", token_line, token_col)
                  else
                    read_char
                    Token.new(TokenType::Not, "!", token_line, token_col)
                  end
                when '<'
                  if peek_char == '='
                    read_char
                    read_char
                    Token.new(TokenType::Le, "<=", token_line, token_col)
                  else
                    read_char
                    Token.new(TokenType::Lt, "<", token_line, token_col)
                  end
                when '>'
                  if peek_char == '='
                    read_char
                    read_char
                    Token.new(TokenType::Ge, ">=", token_line, token_col)
                  else
                    read_char
                    Token.new(TokenType::Gt, ">", token_line, token_col)
                  end
                when '~'
                  if peek_char == '='
                    read_char
                    read_char
                    Token.new(TokenType::Match, "~=", token_line, token_col)
                  else
                    read_char
                    Token.new(TokenType::Match, "~", token_line, token_col)
                  end
                when '&'
                  if peek_char == '&'
                    read_char
                    read_char
                    Token.new(TokenType::And, "&&", token_line, token_col)
                  else
                    read_char
                    Token.new(TokenType::Illegal, "&", token_line, token_col)
                  end
                when '|'
                  if peek_char == '|'
                    read_char
                    read_char
                    Token.new(TokenType::Or, "||", token_line, token_col)
                  else
                    read_char
                    Token.new(TokenType::Illegal, "|", token_line, token_col)
                  end
                when '"', '\''
                  str_val = read_string(@ch)
                  Token.new(TokenType::String, str_val, token_line, token_col)
                else
                  if digit?(@ch)
                    read_number_or_ip(token_line, token_col)
                  elsif ident_start?(@ch)
                    ident = read_identifier
                    case ident.downcase
                    when "and"   then Token.new(TokenType::And, ident, token_line, token_col)
                    when "or"    then Token.new(TokenType::Or, ident, token_line, token_col)
                    when "not"   then Token.new(TokenType::Not, ident, token_line, token_col)
                    when "in"    then Token.new(TokenType::In, ident, token_line, token_col)
                    when "true"  then Token.new(TokenType::True, ident, token_line, token_col)
                    when "false" then Token.new(TokenType::False, ident, token_line, token_col)
                    else Token.new(TokenType::Ident, ident, token_line, token_col)
                    end
                  else
                    illegal_char = @ch
                    read_char
                    Token.new(TokenType::Illegal, illegal_char.to_s, token_line, token_col)
                  end
                end

        token
      end

      # Scans quoted string literal with backslash escapes
      private def read_string(quote_char : Char) : String
        read_char # skip opening quote
        start = @pos

        String.build do |io|
          while @ch != quote_char && @ch != '\0'
            if @ch == '\\'
              read_char
              case @ch
              when 'n'  then io << '\n'
              when 'r'  then io << '\r'
              when 't'  then io << '\t'
              when '\\' then io << '\\'
              when '"'  then io << '"'
              when '\'' then io << '\''
              else io << @ch
              end
            else
              io << @ch
            end
            read_char
          end
        end.tap do
          read_char if @ch == quote_char # skip closing quote
        end
      end

      # Scans numeric literal or dotted-decimal IPv4 address / CIDR prefix
      private def read_number_or_ip(token_line : Int32, token_col : Int32) : Token
        start = @pos

        # Hexadecimal prefix: 0x...
        if @ch == '0' && (peek_char == 'x' || peek_char == 'X')
          read_char
          read_char
          while hex_digit?(@ch)
            read_char
          end
          return Token.new(TokenType::Number, @input[start...@pos], token_line, token_col)
        end

        # Read digits, dots, and optional slash for CIDR
        has_dot = false
        has_slash = false

        while digit?(@ch) || @ch == '.' || @ch == '/'
          has_dot = true if @ch == '.'
          has_slash = true if @ch == '/'
          read_char
        end

        text = @input[start...@pos]

        if has_slash && has_dot
          Token.new(TokenType::Cidr, text, token_line, token_col)
        elsif has_dot
          Token.new(TokenType::IpAddress, text, token_line, token_col)
        else
          Token.new(TokenType::Number, text, token_line, token_col)
        end
      end

      # Scans dotted identifier (e.g. "ip.src", "tcp.dst_port")
      private def read_identifier : String
        start = @pos
        while ident_char?(@ch)
          read_char
        end
        @input[start...@pos]
      end

      private def digit?(c : Char) : Bool
        c >= '0' && c <= '9'
      end

      private def hex_digit?(c : Char) : Bool
        digit?(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
      end

      private def ident_start?(c : Char) : Bool
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
      end

      private def ident_char?(c : Char) : Bool
        ident_start?(c) || digit?(c) || c == '.' || c == '_' || c == '-'
      end
    end
  end
end
