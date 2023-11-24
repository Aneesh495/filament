# =============================================================================
# token.cr - Filament Query Language (FQL) lexical tokens
# =============================================================================
#
# Defines the token vocabulary for the Filament Query Language (FQL).
# FQL supports protocol existence predicates, field comparisons, CIDR prefix
# tests, regular expression matching, and boolean logic.
#
# Author: filament contributors
# License: MIT
# =============================================================================

module Filament
  module Filter
    enum TokenType
      # Literals and Identifiers
      Ident
      Number
      String
      IpAddress
      Cidr
      True
      False

      # Boolean Operators
      And
      Or
      Not

      # Relational and Set Operators
      Eq       # ==
      Ne       # !=
      Lt       # <
      Le       # <=
      Gt       # >
      Ge       # >=
      Match    # ~= (regex / substring match)
      In       # in

      # Delimiters
      LParen   # (
      RParen   # )
      Comma    # ,
      Slash    # /

      # Stream Control
      Eof
      Illegal
    end

    struct Token
      getter type : TokenType
      getter text : String
      getter line : Int32
      getter col : Int32

      def initialize(@type : TokenType, @text : String, @line : Int32, @col : Int32)
      end

      def to_s(io : IO) : Nil
        io << "Token(" << @type << ", \"" << @text << "\", " << @line << ":" << @col << ")"
      end
    end
  end
end
