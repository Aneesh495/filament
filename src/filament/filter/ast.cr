# =============================================================================
# ast.cr - Abstract Syntax Tree (AST) node hierarchy for FQL
# =============================================================================
#
# Represents the parsed syntax tree of a Filament Query Language (FQL)
# expression before compilation into register bytecode.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./token"

module Filament
  module Filter
    abstract class Node
      abstract def to_s(io : IO) : Nil
    end

    abstract class Expr < Node
    end

    # Binary operation: left op right (e.g. a == b, p and q, x in y)
    class BinaryOpExpr < Expr
      getter left : Expr
      getter op : TokenType
      getter right : Expr

      def initialize(@left : Expr, @op : TokenType, @right : Expr)
      end

      def to_s(io : IO) : Nil
        io << "(" << @left << " " << @op << " " << @right << ")"
      end
    end

    # Unary operation: not expr
    class UnaryOpExpr < Expr
      getter op : TokenType
      getter expr : Expr

      def initialize(@op : TokenType, @expr : Expr)
      end

      def to_s(io : IO) : Nil
        io << "!" << @expr
      end
    end

    # Protocol presence predicate (e.g. "tcp", "dns", "http")
    class ProtocolPresentExpr < Expr
      getter protocol_name : String

      def initialize(@protocol_name : String)
      end

      def to_s(io : IO) : Nil
        io << "has(" << @protocol_name << ")"
      end
    end

    # Field reference (e.g. "ip.src", "tcp.dst_port")
    class FieldAccessExpr < Expr
      getter field_name : String

      def initialize(@field_name : String)
      end

      def to_s(io : IO) : Nil
        io << @field_name
      end
    end

    # Numeric literal (integer)
    class NumberLiteralExpr < Expr
      getter value : Int64

      def initialize(@value : Int64)
      end

      def to_s(io : IO) : Nil
        io << @value
      end
    end

    # String literal
    class StringLiteralExpr < Expr
      getter value : String

      def initialize(@value : String)
      end

      def to_s(io : IO) : Nil
        io << '"' << @value << '"'
      end
    end

    # Boolean literal (true / false)
    class BoolLiteralExpr < Expr
      getter value : Bool

      def initialize(@value : Bool)
      end

      def to_s(io : IO) : Nil
        io << @value
      end
    end

    # IPv4 address literal (e.g. 192.168.1.1)
    class IpLiteralExpr < Expr
      getter text : String
      getter ip_u32 : UInt32

      def initialize(@text : String)
        parts = @text.split('.')
        b0 = parts[0]?.try(&.to_u32?) || 0_u32
        b1 = parts[1]?.try(&.to_u32?) || 0_u32
        b2 = parts[2]?.try(&.to_u32?) || 0_u32
        b3 = parts[3]?.try(&.to_u32?) || 0_u32
        @ip_u32 = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
      end

      def to_s(io : IO) : Nil
        io << @text
      end
    end

    # CIDR network prefix literal (e.g. 10.0.0.0/8)
    class CidrLiteralExpr < Expr
      getter text : String
      getter network_u32 : UInt32
      getter mask_u32 : UInt32
      getter prefix_len : Int32

      def initialize(@text : String)
        parts = @text.split('/')
        ip_part = parts[0]? || "0.0.0.0"
        @prefix_len = parts[1]?.try(&.to_i?) || 32

        ip_node = IpLiteralExpr.new(ip_part)
        @mask_u32 = @prefix_len == 0 ? 0_u32 : (0xFFFFFFFF_u32 << (32 - @prefix_len))
        @network_u32 = ip_node.ip_u32 & @mask_u32
      end

      # Tests if an IPv4 integer falls within this CIDR subnet
      def matches?(target_ip : UInt32) : Bool
        (target_ip & @mask_u32) == @network_u32
      end

      def to_s(io : IO) : Nil
        io << @text
      end
    end

    # Set literal for membership testing (e.g. [80, 443, 8080])
    class SetLiteralExpr < Expr
      getter elements : Array(Expr)

      def initialize(@elements : Array(Expr))
      end

      def to_s(io : IO) : Nil
        io << "["
        @elements.each_with_index do |el, i|
          io << ", " if i > 0
          io << el
        end
        io << "]"
      end
    end
  end
end
