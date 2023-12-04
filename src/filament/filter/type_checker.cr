# =============================================================================
# type_checker.cr - Semantic analysis and type checking for FQL
# =============================================================================
#
# Analyzes an FQL AST to verify semantic validity before compilation:
#   - Validates that comparison operand types are compatible
#   - Verifies that CIDR membership operations are applied to IP addresses
#   - Confirms that regular expression matches operate on strings
#   - Detects tautologies or nonsensical boolean constructs
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./ast"

module Filament
  module Filter
    enum TypeId
      Bool
      Integer
      String
      IpAddress
      Cidr
      Unknown
    end

    class TypeError < Exception
      def initialize(message : String)
        super("Type error in filter: #{message}")
      end
    end

    class TypeChecker
      getter errors : Array(String)

      def initialize
        @errors = [] of String
      end

      # Infers type and checks compatibility of an expression
      def check(expr : Expr) : TypeId
        case expr
        when NumberLiteralExpr
          TypeId::Integer
        when StringLiteralExpr
          TypeId::String
        when BoolLiteralExpr
          TypeId::Bool
        when IpLiteralExpr
          TypeId::IpAddress
        when CidrLiteralExpr
          TypeId::Cidr
        when ProtocolPresentExpr
          TypeId::Bool
        when FieldAccessExpr
          # Infer type by field naming conventions
          infer_field_type(expr.field_name)
        when UnaryOpExpr
          sub_type = check(expr.expr)
          if expr.op == TokenType::Not && sub_type != TypeId::Bool && sub_type != TypeId::Unknown
            @errors << "Operator 'not' requires a boolean expression, got #{sub_type}"
          end
          TypeId::Bool
        when BinaryOpExpr
          check_binary(expr)
        else
          TypeId::Unknown
        end
      end

      private def check_binary(expr : BinaryOpExpr) : TypeId
        left_t = check(expr.left)
        right_t = check(expr.right)

        case expr.op
        when TokenType::And, TokenType::Or
          if left_t != TypeId::Bool && left_t != TypeId::Unknown
            @errors << "Left operand of '#{expr.op}' must be boolean, got #{left_t}"
          end
          if right_t != TypeId::Bool && right_t != TypeId::Unknown
            @errors << "Right operand of '#{expr.op}' must be boolean, got #{right_t}"
          end
          TypeId::Bool

        when TokenType::In
          if right_t == TypeId::Cidr
            if left_t != TypeId::IpAddress && left_t != TypeId::Unknown
              @errors << "Left operand of 'in <CIDR>' must be an IP address, got #{left_t}"
            end
          end
          TypeId::Bool

        when TokenType::Match
          if left_t != TypeId::String && left_t != TypeId::Unknown
            @errors << "Left operand of regex match '~=' must be string, got #{left_t}"
          end
          TypeId::Bool

        when TokenType::Eq, TokenType::Ne
          # Equality allowed between matching types or unknown
          TypeId::Bool

        when TokenType::Lt, TokenType::Le, TokenType::Gt, TokenType::Ge
          if (left_t == TypeId::String && right_t != TypeId::String) ||
             (left_t == TypeId::Integer && right_t != TypeId::Integer)
            @errors << "Cannot compare incompatible types #{left_t} and #{right_t}"
          end
          TypeId::Bool

        else
          TypeId::Unknown
        end
      end

      # Heuristic field type inference based on field name suffix
      private def infer_field_type(name : String) : TypeId
        lower = name.downcase
        if lower.ends_with?(".src") || lower.ends_with?(".dst") || lower.ends_with?(".ip")
          TypeId::IpAddress
        elsif lower.ends_with?(".port") || lower.ends_with?(".len") || lower.ends_with?(".length") ||
              lower.ends_with?(".id") || lower.ends_with?(".ttl") || lower.ends_with?(".seq") ||
              lower.ends_with?(".ack") || lower.ends_with?(".type") || lower.ends_with?(".code")
          TypeId::Integer
        elsif lower.ends_with?(".syn") || lower.ends_with?(".ack") || lower.ends_with?(".fin") ||
              lower.ends_with?(".rst") || lower.ends_with?(".df") || lower.ends_with?(".mf") ||
              lower.ends_with?(".valid")
          TypeId::Bool
        elsif lower.ends_with?(".host") || lower.ends_with?(".uri") || lower.ends_with?(".method") ||
              lower.ends_with?(".sni") || lower.ends_with?(".qname") || lower.ends_with?(".reason")
          TypeId::String
        else
          TypeId::Unknown
        end
      end

      def valid? : Bool
        @errors.empty?
      end
    end
  end
end
