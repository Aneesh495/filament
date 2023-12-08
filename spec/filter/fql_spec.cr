require "../spec_helper"
require "../../src/filament/filter/lexer"
require "../../src/filament/filter/parser"
require "../../src/filament/filter/type_checker"
require "../../src/filament/filter/compiler"
require "../../src/filament/filter/vm"
require "../../src/filament/dissect/layer2/ethernet"
require "../../src/filament/dissect/layer3/ipv4"
require "../../src/filament/dissect/layer4/tcp"

describe Filament::Filter::Lexer do
  it "scans identifiers, operators, numbers, and CIDR blocks" do
    input = "ip.src in 10.0.0.0/8 and tcp.dst_port == 443"
    lexer = Filament::Filter::Lexer.new(input)

    tokens = [] of Filament::Filter::Token
    loop do
      tok = lexer.next_token
      tokens << tok
      break if tok.type == Filament::Filter::TokenType::Eof
    end

    types = tokens.map(&.type)
    types.should eq([
      Filament::Filter::TokenType::Ident,
      Filament::Filter::TokenType::In,
      Filament::Filter::TokenType::Cidr,
      Filament::Filter::TokenType::And,
      Filament::Filter::TokenType::Ident,
      Filament::Filter::TokenType::Eq,
      Filament::Filter::TokenType::Number,
      Filament::Filter::TokenType::Eof
    ])
  end
end

describe Filament::Filter::Parser do
  it "respects operator precedence between AND and OR" do
    # a or b and c should parse as (a or (b and c))
    ast = Filament::Filter::Parser.parse("tcp or udp and dns")
    ast.should_not be_nil

    bin = ast.as(Filament::Filter::BinaryOpExpr)
    bin.op.should eq(Filament::Filter::TokenType::Or)
    bin.right.is_a?(Filament::Filter::BinaryOpExpr).should be_true
  end

  it "parses grouped parentheses overriding natural precedence" do
    # (a or b) and c
    ast = Filament::Filter::Parser.parse("(tcp or udp) and dns")
    ast.should_not be_nil

    bin = ast.as(Filament::Filter::BinaryOpExpr)
    bin.op.should eq(Filament::Filter::TokenType::And)
    bin.left.is_a?(Filament::Filter::BinaryOpExpr).should be_true
  end
end

describe Filament::Filter::FilterVM do
  # Create a synthetic decoded packet with Ethernet, IPv4, TCP (dst_port 443)
  raw_bytes = Bytes[
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0x08, 0x00,                         # IPv4
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x01, 0x40, 0x00,
    0x40, 0x06, 0x00, 0x00,             # Proto 6 (TCP)
    0xc0, 0xa8, 0x01, 0x32,             # 192.168.1.50
    0x08, 0x08, 0x08, 0x08,             # 8.8.8.8
    0x04, 0xd2, 0x01, 0xbb,             # 1234 -> 443
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x02, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00
  ]

  raw_pkt = Filament::Capture::RawPacket.new(
    data: raw_bytes,
    timestamp: Time.utc,
    original_length: raw_bytes.size.to_u32,
    capture_length: raw_bytes.size.to_u32,
    link_type: Filament::Capture::LinkType::Ethernet
  )

  # Register dissectors in global registry
  Filament::Dissect::DissectorRegistry.instance.register(Filament::Dissect::Layer2::EthernetDissector.new)
  Filament::Dissect::DissectorRegistry.instance.register(Filament::Dissect::Layer3::IPv4Dissector.new)
  Filament::Dissect::DissectorRegistry.instance.register(Filament::Dissect::Layer4::TcpDissector.new)

  decoded = Filament::Dissect::DecodedPacket.decode(raw_pkt)

  it "matches protocol presence query 'tcp'" do
    ast = Filament::Filter::Parser.parse("tcp")
    compiled = Filament::Filter::Compiler.compile(ast)
    Filament::Filter::FilterVM.match?(compiled, decoded).should be_true
  end

  it "rejects protocol presence query 'udp'" do
    ast = Filament::Filter::Parser.parse("udp")
    compiled = Filament::Filter::Compiler.compile(ast)
    Filament::Filter::FilterVM.match?(compiled, decoded).should be_false
  end

  it "evaluates port comparison 'tcp.dst_port == 443'" do
    ast = Filament::Filter::Parser.parse("tcp.dst_port == 443")
    compiled = Filament::Filter::Compiler.compile(ast)
    Filament::Filter::FilterVM.match?(compiled, decoded).should be_true
  end

  it "evaluates compound filter 'tcp and tcp.dst_port == 443'" do
    ast = Filament::Filter::Parser.parse("tcp and tcp.dst_port == 443")
    compiled = Filament::Filter::Compiler.compile(ast)
    Filament::Filter::FilterVM.match?(compiled, decoded).should be_true
  end

  it "rejects failing compound filter 'tcp and tcp.dst_port == 80'" do
    ast = Filament::Filter::Parser.parse("tcp and tcp.dst_port == 80")
    compiled = Filament::Filter::Compiler.compile(ast)
    Filament::Filter::FilterVM.match?(compiled, decoded).should be_false
  end
end
