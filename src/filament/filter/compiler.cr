# =============================================================================
# compiler.cr - Bytecode compiler for the FQL register virtual machine
# =============================================================================
#
# Compiles an FQL AST into linear register bytecode with short-circuit jump
# optimization for boolean disjunctions and conjunctions.
#
# Author: filament contributors
# License: MIT
# =============================================================================

require "./ast"
require "./bytecode"

module Filament
  module Filter
    class Compiler
      @instructions = [] of Instruction
      @constants = [] of FilterConstant
      @next_reg = 0_u8
      @max_reg = 0_u8

      def initialize
      end

      # Compiles an AST expression into a CompiledFilter object
      def self.compile(expr : Expr?) : CompiledFilter
        return CompiledFilter.accept_all unless expr
        compiler = new
        res_reg = compiler.compile_expr(expr)
        compiler.emit(Instruction.new(Opcode::Return, src1: res_reg))
        CompiledFilter.new(compiler.@instructions, compiler.@constants, (compiler.@max_reg + 1).to_i32)
      end

      # Allocates a virtual register
      private def alloc_reg : UInt8
        reg = @next_reg
        @next_reg += 1_u8
        @max_reg = Math.max(@max_reg, @next_reg)
        reg
      end

      private def free_reg : Nil
        @next_reg -= 1_u8 if @next_reg > 0_u8
      end

      # Adds a value to the constant pool, returning its index
      private def add_const(val : FilterConstant) : UInt16
        idx = @constants.index(val)
        if idx
          idx.to_u16
        else
          new_idx = @constants.size.to_u16
          @constants << val
          new_idx
        end
      end

      private def emit(ins : Instruction) : Int32
        pos = @instructions.size
        @instructions << ins
        pos
      end

      # Compiles an expression node and returns the register containing its result
      def compile_expr(expr : Expr) : UInt8
        case expr
        when NumberLiteralExpr
          dst = alloc_reg
          c_idx = add_const(expr.value)
          emit(Instruction.new(Opcode::LoadConst, dst: dst, const_idx: c_idx))
          dst

        when StringLiteralExpr
          dst = alloc_reg
          c_idx = add_const(expr.value)
          emit(Instruction.new(Opcode::LoadConst, dst: dst, const_idx: c_idx))
          dst

        when BoolLiteralExpr
          dst = alloc_reg
          c_idx = add_const(expr.value)
          emit(Instruction.new(Opcode::LoadConst, dst: dst, const_idx: c_idx))
          dst

        when IpLiteralExpr
          dst = alloc_reg
          c_idx = add_const(expr.text)
          emit(Instruction.new(Opcode::LoadConst, dst: dst, const_idx: c_idx))
          dst

        when CidrLiteralExpr
          dst = alloc_reg
          c_idx = add_const(expr)
          emit(Instruction.new(Opcode::LoadConst, dst: dst, const_idx: c_idx))
          dst

        when ProtocolPresentExpr
          dst = alloc_reg
          c_idx = add_const(expr.protocol_name)
          emit(Instruction.new(Opcode::CheckProto, dst: dst, const_idx: c_idx))
          dst

        when FieldAccessExpr
          dst = alloc_reg
          c_idx = add_const(expr.field_name)
          emit(Instruction.new(Opcode::LoadField, dst: dst, const_idx: c_idx))
          dst

        when UnaryOpExpr
          sub_reg = compile_expr(expr.expr)
          dst = alloc_reg
          emit(Instruction.new(Opcode::LogicalNot, dst: dst, src1: sub_reg))
          free_reg # free sub_reg
          dst

        when BinaryOpExpr
          compile_binary(expr)

        else
          dst = alloc_reg
          c_idx = add_const(true)
          emit(Instruction.new(Opcode::LoadConst, dst: dst, const_idx: c_idx))
          dst
        end
      end

      # Compiles binary operators with short-circuit evaluation for AND / OR
      private def compile_binary(expr : BinaryOpExpr) : UInt8
        case expr.op
        when TokenType::And
          compile_short_circuit_and(expr)
        when TokenType::Or
          compile_short_circuit_or(expr)
        else
          left_reg = compile_expr(expr.left)
          right_reg = compile_expr(expr.right)
          dst = alloc_reg

          op_code = case expr.op
                    when TokenType::Eq    then Opcode::CmpEq
                    when TokenType::Ne    then Opcode::CmpNe
                    when TokenType::Lt    then Opcode::CmpLt
                    when TokenType::Le    then Opcode::CmpLe
                    when TokenType::Gt    then Opcode::CmpGt
                    when TokenType::Ge    then Opcode::CmpGe
                    when TokenType::Match then Opcode::CmpMatch
                    when TokenType::In    then Opcode::CheckCidr
                    else Opcode::CmpEq
                    end

          emit(Instruction.new(op_code, dst: dst, src1: left_reg, src2: right_reg))
          free_reg # right_reg
          free_reg # left_reg
          dst
        end
      end

      # Short-circuit logical AND
      private def compile_short_circuit_and(expr : BinaryOpExpr) : UInt8
        dst = alloc_reg
        left_reg = compile_expr(expr.left)

        # Emit jump-if-false past right evaluation
        jump_idx = emit(Instruction.new(Opcode::JumpIfFalse, src1: left_reg, target: 0))

        right_reg = compile_expr(expr.right)
        # Result is right_reg if left was true
        emit(Instruction.new(Opcode::CmpEq, dst: dst, src1: right_reg, src2: right_reg)) # copy/test

        end_target = @instructions.size
        # Patch false jump to bypass right side and load false
        @instructions[jump_idx] = @instructions[jump_idx].with_target(end_target)

        free_reg # right_reg
        free_reg # left_reg
        dst
      end

      # Short-circuit logical OR
      private def compile_short_circuit_or(expr : BinaryOpExpr) : UInt8
        dst = alloc_reg
        left_reg = compile_expr(expr.left)

        # Emit jump-if-true past right evaluation
        jump_idx = emit(Instruction.new(Opcode::JumpIfTrue, src1: left_reg, target: 0))

        right_reg = compile_expr(expr.right)
        emit(Instruction.new(Opcode::CmpEq, dst: dst, src1: right_reg, src2: right_reg))

        end_target = @instructions.size
        @instructions[jump_idx] = @instructions[jump_idx].with_target(end_target)

        free_reg
        free_reg
        dst
      end
    end
  end
end
