# =============================================================================
# vm.cr - High-speed register virtual machine evaluator for FQL
# =============================================================================
#
# Evaluates compiled FQL bytecode against decoded packet records.
# Designed for minimal allocation overhead in critical packet filter loops.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./bytecode"
require "../dissect/decoded_packet"

module Filament
  module Filter
    class FilterVM
      # Evaluates a compiled filter against a decoded packet. Returns true if match.
      def self.match?(filter : CompiledFilter, packet : Dissect::DecodedPacket) : Bool
        insts = filter.instructions
        consts = filter.constants
        return true if insts.empty?

        # Allocate virtual registers array
        regs = Array(Dissect::FieldValue).new(filter.register_count, nil)

        pc = 0
        while pc < insts.size
          ins = insts[pc]

          case ins.op
          when Opcode::LoadConst
            c_val = consts[ins.const_idx]
            regs[ins.dst] = case c_val
                            when Int64 then c_val
                            when String then c_val
                            when Bool then c_val
                            when UInt32 then c_val
                            when CidrLiteralExpr then c_val.text
                            else nil
                            end

          when Opcode::LoadField
            fname = consts[ins.const_idx].as(String)
            val = packet.field(fname)
            regs[ins.dst] = val

          when Opcode::CheckProto
            pname = consts[ins.const_idx].as(String).downcase
            has = packet.layers.any? do |l|
              l_name = l.protocol.to_s.downcase
              l_name == pname || (l_name == "ipv4" && pname == "ip")
            end
            regs[ins.dst] = has

          when Opcode::CmpEq
            v1 = regs[ins.src1]
            v2 = regs[ins.src2]
            regs[ins.dst] = values_equal?(v1, v2)

          when Opcode::CmpNe
            v1 = regs[ins.src1]
            v2 = regs[ins.src2]
            regs[ins.dst] = !values_equal?(v1, v2)

          when Opcode::CmpLt
            regs[ins.dst] = compare_values(regs[ins.src1], regs[ins.src2]) < 0

          when Opcode::CmpLe
            regs[ins.dst] = compare_values(regs[ins.src1], regs[ins.src2]) <= 0

          when Opcode::CmpGt
            regs[ins.dst] = compare_values(regs[ins.src1], regs[ins.src2]) > 0

          when Opcode::CmpGe
            regs[ins.dst] = compare_values(regs[ins.src1], regs[ins.src2]) >= 0

          when Opcode::CmpMatch
            v1 = regs[ins.src1]
            v2 = regs[ins.src2]
            if v1.is_a?(String) && v2.is_a?(String)
              regs[ins.dst] = v1.includes?(v2)
            else
              regs[ins.dst] = false
            end

          when Opcode::CheckCidr
            ip_val = regs[ins.src1]
            cidr_val = consts[ins.const_idx]? || regs[ins.src2]

            regs[ins.dst] = if ip_val.is_a?(String) && cidr_val.is_a?(CidrLiteralExpr)
                              target_ip = IpLiteralExpr.new(ip_val).ip_u32
                              cidr_val.matches?(target_ip)
                            else
                              false
                            end

          when Opcode::LogicalNot
            v = regs[ins.src1]
            regs[ins.dst] = !truthy?(v)

          when Opcode::JumpIfFalse
            v = regs[ins.src1]
            unless truthy?(v)
              pc = ins.target
              next
            end

          when Opcode::JumpIfTrue
            v = regs[ins.src1]
            if truthy?(v)
              pc = ins.target
              next
            end

          when Opcode::Jump
            pc = ins.target
            next

          when Opcode::Return
            res = regs[ins.src1]
            return truthy?(res)
          end

          pc += 1
        end

        true
      end

      # Coerces any FieldValue to boolean truthiness
      private def self.truthy?(val : Dissect::FieldValue) : Bool
        case val
        when nil    then false
        when Bool   then val
        when Int    then val != 0
        when String then !val.empty?
        else true
        end
      end

      # Compares two polymorphic field values
      private def self.values_equal?(v1 : Dissect::FieldValue, v2 : Dissect::FieldValue) : Bool
        return true if v1 == v2

        # Allow numeric comparison between different integer widths
        if v1.is_a?(Int) && v2.is_a?(Int)
          return v1.to_i64 == v2.to_i64
        end

        # String comparison
        if v1.is_a?(String) && v2.is_a?(String)
          return v1 == v2
        end

        false
      end

      private def self.compare_values(v1 : Dissect::FieldValue, v2 : Dissect::FieldValue) : Int32
        if v1.is_a?(Int) && v2.is_a?(Int)
          return v1.to_i64 <=> v2.to_i64
        elsif v1.is_a?(String) && v2.is_a?(String)
          return v1 <=> v2
        end
        0
      end
    end
  end
end
