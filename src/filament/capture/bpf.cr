# =============================================================================
# bpf.cr - Berkeley Packet Filter bytecode compiler and virtual machine
# =============================================================================
#
# Implements the classic Berkeley Packet Filter (cBPF) architecture described
# by McCanne and Jacobson in their 1993 USENIX paper "The BSD Packet Filter:
# A New Architecture for User-level Packet Capture".
#
# The cBPF machine is an idealized register machine with:
#   - An accumulator register (A) of 32 bits
#   - An index register (X) of 32 bits
#   - A small scratch memory store of 16 words (M[0..15])
#   - An implicit program counter
#
# Instructions operate on packet data directly using absolute or indirect
# offsets. Conditional jumps have two branch targets (jump true 'jt' and
# jump false 'jf') expressed as relative PC offsets, guaranteeing acyclic
# execution with zero backward jumps.
#
# Author: filament contributors
# License: MIT
# =============================================================================

module Filament
  module Capture
    # Instruction classes (bits 0-2 of opcode)
    module BpfClass
      LD   = 0x00U16
      LDX  = 0x01U16
      ST   = 0x02U16
      STX  = 0x03U16
      ALU  = 0x04U16
      JMP  = 0x05U16
      RET  = 0x06U16
      MISC = 0x07U16
    end

    # Size modifiers for load/store (bits 3-4 of opcode)
    module BpfSize
      W = 0x00U16 # 32-bit word
      H = 0x08U16 # 16-bit half-word
      B = 0x10U16 # 8-bit byte
    end

    # Addressing modes (bits 5-7 of opcode)
    module BpfMode
      IMM = 0x00U16 # Immediate value [k]
      ABS = 0x20U16 # Absolute packet offset [k]
      IND = 0x40U16 # Indirect packet offset [X + k]
      MEM = 0x60U16 # Scratch memory [k]
      LEN = 0x80U16 # Packet length
      MSH = 0xA0U16 # IPv4 4*(P[k:1]&0xf) into X
    end

    # ALU and JMP sub-operations (bits 4-7 of opcode)
    module BpfOp
      ADD = 0x00U16
      SUB = 0x10U16
      MUL = 0x20U16
      DIV = 0x30U16
      OR  = 0x40U16
      AND = 0x50U16
      LSH = 0x60U16
      RSH = 0x70U16
      NEG = 0x80U16
      MOD = 0x90U16
      XOR = 0xA0U16

      JA   = 0x00U16 # Jump always
      JEQ  = 0x10U16 # Jump if equal
      JGT  = 0x20U16 # Jump if greater than
      JGE  = 0x30U16 # Jump if greater or equal
      JSET = 0x40U16 # Jump if bitmask test non-zero
    end

    # Source operand flag (bit 3 of opcode)
    module BpfSrc
      K = 0x00U16 # Constant k
      X = 0x08U16 # Register X
      A = 0x10U16 # Register A (used in RET)
    end

    # A single 64-bit BPF instruction representation matching the kernel layout
    struct BpfInstruction
      getter code : UInt16
      getter jt : UInt8
      getter jf : UInt8
      getter k : UInt32

      def initialize(@code : UInt16, @jt : UInt8, @jf : UInt8, @k : UInt32)
      end

      # Convenience constructor for non-branching instructions
      def self.stmt(code : UInt16, k : UInt32) : BpfInstruction
        new(code, 0U8, 0U8, k)
      end

      # Convenience constructor for conditional branch instructions
      def self.jump(code : UInt16, jt : UInt8, jf : UInt8, k : UInt32) : BpfInstruction
        new(code, jt, jf, k)
      end

      def to_s(io : IO) : Nil
        io << "BPF{code=0x" << @code.to_s(16) << ", jt=" << @jt << ", jf=" << @jf << ", k=0x" << @k.to_s(16) << "}"
      end
    end

    # Compiled program represented as an immutable array of instructions
    class BpfProgram
      getter instructions : Array(BpfInstruction)

      def initialize(@instructions : Array(BpfInstruction))
      end

      # Creates an accept-all filter program (returns snaplen)
      def self.accept_all(snap_len : UInt32 = 65535U32) : BpfProgram
        new([
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, snap_len)
        ])
      end

      # Creates a reject-all filter program
      def self.reject_all : BpfProgram
        new([
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, 0U32)
        ])
      end

      def size : Int32
        @instructions.size
      end
    end

    # Virtual machine execution engine for BPF bytecode
    class BpfEvaluator
      # Evaluates a compiled BPF program against raw packet bytes.
      # Returns captured length (number of bytes to retain), or 0 if rejected.
      def self.evaluate(program : BpfProgram, packet : Bytes, original_len : UInt32? = nil) : UInt32
        insts = program.instructions
        return 0U32 if insts.empty?

        pc = 0
        a = 0U32
        x = 0U32
        mem = StaticArray(UInt32, 16).new(0U32)
        wire_len = (original_len || packet.size.to_u32)
        cap_len = packet.size

        while pc < insts.size
          ins = insts[pc]
          cls = ins.code & 0x07U16
          mode = ins.code & 0xE0U16
          size = ins.code & 0x18U16
          op = ins.code & 0xF0U16
          src = ins.code & 0x08U16

          case cls
          when BpfClass::LD
            case mode
            when BpfMode::IMM
              a = ins.k
            when BpfMode::ABS
              offset = ins.k.to_i32
              case size
              when BpfSize::W
                return 0U32 if offset + 4 > cap_len
                a = (packet[offset].to_u32 << 24) |
                    (packet[offset + 1].to_u32 << 16) |
                    (packet[offset + 2].to_u32 << 8) |
                    packet[offset + 3].to_u32
              when BpfSize::H
                return 0U32 if offset + 2 > cap_len
                a = (packet[offset].to_u32 << 8) | packet[offset + 1].to_u32
              when BpfSize::B
                return 0U32 if offset + 1 > cap_len
                a = packet[offset].to_u32
              end
            when BpfMode::IND
              offset = (x + ins.k).to_i32
              case size
              when BpfSize::W
                return 0U32 if offset + 4 > cap_len
                a = (packet[offset].to_u32 << 24) |
                    (packet[offset + 1].to_u32 << 16) |
                    (packet[offset + 2].to_u32 << 8) |
                    packet[offset + 3].to_u32
              when BpfSize::H
                return 0U32 if offset + 2 > cap_len
                a = (packet[offset].to_u32 << 8) | packet[offset + 1].to_u32
              when BpfSize::B
                return 0U32 if offset + 1 > cap_len
                a = packet[offset].to_u32
              end
            when BpfMode::MEM
              a = mem[ins.k & 0x0FU32]
            when BpfMode::LEN
              a = wire_len
            end

          when BpfClass::LDX
            case mode
            when BpfMode::IMM
              x = ins.k
            when BpfMode::MEM
              x = mem[ins.k & 0x0FU32]
            when BpfMode::LEN
              x = wire_len
            when BpfMode::MSH
              # IPv4 header length calculation: 4 * (packet[k] & 0x0F)
              offset = ins.k.to_i32
              return 0U32 if offset >= cap_len
              x = ((packet[offset] & 0x0FU8) * 4U8).to_u32
            end

          when BpfClass::ST
            mem[ins.k & 0x0FU32] = a

          when BpfClass::STX
            mem[ins.k & 0x0FU32] = x

          when BpfClass::ALU
            rhs = (src == BpfSrc::X) ? x : ins.k
            case op
            when BpfOp::ADD
              a = a &+ rhs
            when BpfOp::SUB
              a = a &- rhs
            when BpfOp::MUL
              a = a &* rhs
            when BpfOp::DIV
              return 0U32 if rhs == 0U32
              a = a // rhs
            when BpfOp::MOD
              return 0U32 if rhs == 0U32
              a = a % rhs
            when BpfOp::AND
              a = a & rhs
            when BpfOp::OR
              a = a | rhs
            when BpfOp::XOR
              a = a ^ rhs
            when BpfOp::LSH
              a = (rhs >= 32) ? 0U32 : (a << rhs)
            when BpfOp::RSH
              a = (rhs >= 32) ? 0U32 : (a >> rhs)
            when BpfOp::NEG
              a = 0U32 &- a
            end

          when BpfClass::JMP
            case op
            when BpfOp::JA
              pc += ins.k.to_i32 + 1
              next
            when BpfOp::JEQ
              target = (src == BpfSrc::X) ? x : ins.k
              pc += (a == target ? ins.jt : ins.jf).to_i32 + 1
              next
            when BpfOp::JGT
              target = (src == BpfSrc::X) ? x : ins.k
              pc += (a > target ? ins.jt : ins.jf).to_i32 + 1
              next
            when BpfOp::JGE
              target = (src == BpfSrc::X) ? x : ins.k
              pc += (a >= target ? ins.jt : ins.jf).to_i32 + 1
              next
            when BpfOp::JSET
              target = (src == BpfSrc::X) ? x : ins.k
              pc += ((a & target) != 0U32 ? ins.jt : ins.jf).to_i32 + 1
              next
            end

          when BpfClass::RET
            return (src == BpfSrc::A) ? a : ins.k

          when BpfClass::MISC
            # Transfer operations
            if ins.k == 0U32 # TAX: A -> X
              x = a
            elsif ins.k == 1U32 # TXA: X -> A
              a = x
            end
          end

          pc += 1
        end

        0U32
      end
    end

    # High-level compiler converting common filter expressions into cBPF programs
    class BpfCompiler
      # Compiles simple expression syntax into a cBPF bytecode program.
      # Supported patterns:
      #   - "ip", "ipv6", "arp"
      #   - "tcp", "udp", "icmp"
      #   - "port 80", "tcp port 443", "udp port 53"
      #   - "src port 80", "dst port 80"
      #   - "host 192.168.1.1", "src host 10.0.0.1", "dst host 10.0.0.2"
      def self.compile(expression : String, snap_len : UInt32 = 65535U32) : BpfProgram
        expr = expression.strip.downcase
        return BpfProgram.accept_all(snap_len) if expr.empty? || expr == "all"

        case expr
        when "ip"
          compile_ethertype(0x0800U16, snap_len)
        when "ipv6"
          compile_ethertype(0x86DDU16, snap_len)
        when "arp"
          compile_ethertype(0x0806U16, snap_len)
        when "tcp"
          compile_ip_proto(6U8, snap_len)
        when "udp"
          compile_ip_proto(17U8, snap_len)
        when "icmp"
          compile_ip_proto(1U8, snap_len)
        else
          if expr.starts_with?("port ")
            port = expr[5..].strip.to_u16? || 0U16
            compile_port(port, :any, snap_len)
          elsif expr.starts_with?("tcp port ")
            port = expr[9..].strip.to_u16? || 0U16
            compile_tcp_port(port, :any, snap_len)
          elsif expr.starts_with?("udp port ")
            port = expr[9..].strip.to_u16? || 0U16
            compile_udp_port(port, :any, snap_len)
          elsif expr.starts_with?("host ")
            ip_str = expr[5..].strip
            compile_host(ip_str, :any, snap_len)
          elsif expr.starts_with?("src host ")
            ip_str = expr[9..].strip
            compile_host(ip_str, :src, snap_len)
          elsif expr.starts_with?("dst host ")
            ip_str = expr[9..].strip
            compile_host(ip_str, :dst, snap_len)
          else
            # Default fallback: accept all
            BpfProgram.accept_all(snap_len)
          end
        end
      end

      # Generates BPF program checking Ethernet frame EtherType at offset 12
      private def self.compile_ethertype(ethertype : UInt16, snap_len : UInt32) : BpfProgram
        instructions = [
          # Load halfword from offset 12 (EtherType)
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::ABS, 12U32),
          # Jump if equal to ethertype: jt=+0, jf=+1
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 1U8, ethertype.to_u32),
          # Match: return snap_len
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, snap_len),
          # Reject: return 0
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, 0U32),
        ]
        BpfProgram.new(instructions)
      end

      # Generates BPF program checking IPv4 protocol field (byte 23 = eth 14 + ip 9)
      private def self.compile_ip_proto(proto : UInt8, snap_len : UInt32) : BpfProgram
        instructions = [
          # Verify EtherType == 0x0800 (IPv4)
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::ABS, 12U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 3U8, 0x0800U32),
          # Load protocol byte at offset 23 (14 + 9)
          BpfInstruction.stmt(BpfClass::LD | BpfSize::B | BpfMode::ABS, 23U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 1U8, proto.to_u32),
          # Match
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, snap_len),
          # Reject
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, 0U32),
        ]
        BpfProgram.new(instructions)
      end

      # Checks TCP or UDP port using IPv4 header length calculation
      private def self.compile_port(port : UInt16, dir : Symbol, snap_len : UInt32) : BpfProgram
        # 1. Check EtherType == IPv4
        # 2. Compute IPv4 header length into X (MSH offset 14)
        # 3. Load transport port at offset 14 + X + port_offset
        instructions = [
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::ABS, 12U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 6U8, 0x0800U32),
          # MSH: X = 4 * (packet[14] & 0xf)
          BpfInstruction.stmt(BpfClass::LDX | BpfMode::MSH, 14U32),
          # Load src port at 14 + X
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::IND, 14U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 2U8, 0U8, port.to_u32),
          # Load dst port at 14 + X + 2
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::IND, 16U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 1U8, port.to_u32),
          # Match
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, snap_len),
          # Reject
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, 0U32),
        ]
        BpfProgram.new(instructions)
      end

      private def self.compile_tcp_port(port : UInt16, dir : Symbol, snap_len : UInt32) : BpfProgram
        instructions = [
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::ABS, 12U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 8U8, 0x0800U32),
          # Check proto == 6 (TCP)
          BpfInstruction.stmt(BpfClass::LD | BpfSize::B | BpfMode::ABS, 23U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 6U8, 6U32),
          # MSH
          BpfInstruction.stmt(BpfClass::LDX | BpfMode::MSH, 14U32),
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::IND, 14U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 2U8, 0U8, port.to_u32),
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::IND, 16U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 1U8, port.to_u32),
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, snap_len),
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, 0U32),
        ]
        BpfProgram.new(instructions)
      end

      private def self.compile_udp_port(port : UInt16, dir : Symbol, snap_len : UInt32) : BpfProgram
        instructions = [
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::ABS, 12U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 8U8, 0x0800U32),
          # Check proto == 17 (UDP)
          BpfInstruction.stmt(BpfClass::LD | BpfSize::B | BpfMode::ABS, 23U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 6U8, 17U32),
          # MSH
          BpfInstruction.stmt(BpfClass::LDX | BpfMode::MSH, 14U32),
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::IND, 14U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 2U8, 0U8, port.to_u32),
          BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::IND, 16U32),
          BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 1U8, port.to_u32),
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, snap_len),
          BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, 0U32),
        ]
        BpfProgram.new(instructions)
      end

      # Matches an IPv4 address (in dotted decimal) at src (offset 26) or dst (offset 30)
      private def self.compile_host(ip_str : String, dir : Symbol, snap_len : UInt32) : BpfProgram
        parts = ip_str.split(".")
        return BpfProgram.reject_all unless parts.size == 4
        b0 = parts[0].to_u32? || 0U32
        b1 = parts[1].to_u32? || 0U32
        b2 = parts[2].to_u32? || 0U32
        b3 = parts[3].to_u32? || 0U32
        ip_val = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

        case dir
        when :src
          instructions = [
            BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::ABS, 12U32),
            BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 3U8, 0x0800U32),
            BpfInstruction.stmt(BpfClass::LD | BpfSize::W | BpfMode::ABS, 26U32),
            BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 1U8, ip_val),
            BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, snap_len),
            BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, 0U32),
          ]
        when :dst
          instructions = [
            BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::ABS, 12U32),
            BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 3U8, 0x0800U32),
            BpfInstruction.stmt(BpfClass::LD | BpfSize::W | BpfMode::ABS, 30U32),
            BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 1U8, ip_val),
            BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, snap_len),
            BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, 0U32),
          ]
        else
          # Any direction (src or dst)
          instructions = [
            BpfInstruction.stmt(BpfClass::LD | BpfSize::H | BpfMode::ABS, 12U32),
            BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 5U8, 0x0800U32),
            BpfInstruction.stmt(BpfClass::LD | BpfSize::W | BpfMode::ABS, 26U32),
            BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 2U8, 0U8, ip_val),
            BpfInstruction.stmt(BpfClass::LD | BpfSize::W | BpfMode::ABS, 30U32),
            BpfInstruction.jump(BpfClass::JMP | BpfOp::JEQ | BpfSrc::K, 0U8, 1U8, ip_val),
            BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, snap_len),
            BpfInstruction.stmt(BpfClass::RET | BpfSrc::K, 0U32),
          ]
        end
        BpfProgram.new(instructions)
      end
    end
  end
end
