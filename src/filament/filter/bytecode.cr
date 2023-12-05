# =============================================================================
# bytecode.cr - FQL Register Virtual Machine instruction set
# =============================================================================
#
# Defines the bytecode instruction set architecture (ISA) for the FQL virtual
# machine. The machine uses a register-based design with short-circuit branching
# to achieve high evaluation speed on packet streams.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./ast"

module Filament
  module Filter
    enum Opcode : UInt8
      # Constant and Field Loading
      LoadConst
      LoadField
      CheckProto

      # Comparisons
      CmpEq
      CmpNe
      CmpLt
      CmpLe
      CmpGt
      CmpGe
      CmpMatch
      CheckCidr

      # Logic
      LogicalNot

      # Control Flow
      JumpIfFalse
      JumpIfTrue
      Jump
      Return
    end

    struct Instruction
      getter op : Opcode
      getter dst : UInt8
      getter src1 : UInt8
      getter src2 : UInt8
      getter const_idx : UInt16
      getter target : Int32

      def initialize(
        @op : Opcode,
        @dst : UInt8 = 0_u8,
        @src1 : UInt8 = 0_u8,
        @src2 : UInt8 = 0_u8,
        @const_idx : UInt16 = 0_u16,
        @target : Int32 = 0
      )
      end

      # Factory constructor with patched branch target
      def with_target(new_target : Int32) : Instruction
        Instruction.new(@op, @dst, @src1, @src2, @const_idx, new_target)
      end
    end

    # Heterogeneous constant pool value
    alias FilterConstant = Int64 | String | Bool | UInt32 | CidrLiteralExpr

    # Compiled filter artifact ready for VM execution
    class CompiledFilter
      getter instructions : Array(Instruction)
      getter constants : Array(FilterConstant)
      getter register_count : Int32

      def initialize(
        @instructions : Array(Instruction),
        @constants : Array(FilterConstant),
        @register_count : Int32
      )
      end

      # Creates an unconditional accept-all compiled filter
      def self.accept_all : CompiledFilter
        insts = [
          Instruction.new(Opcode::LoadConst, dst: 0_u8, const_idx: 0_u16),
          Instruction.new(Opcode::Return, src1: 0_u8)
        ]
        new(insts, [true.as(FilterConstant)], 1)
      end
    end
  end
end
