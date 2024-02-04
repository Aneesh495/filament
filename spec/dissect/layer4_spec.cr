require "../spec_helper"
require "../../src/filament/dissect/layer4/udp"
require "../../src/filament/dissect/layer4/tcp"
require "../../src/filament/dissect/layer4/tcp_seq"
require "../../src/filament/dissect/layer4/tcp_stream"

describe Filament::Dissect::Layer4::UdpDissector do
  dissector = Filament::Dissect::Layer4::UdpDissector.new

  it "dissects UDP datagram header" do
    data = Bytes[
      0x04, 0xd2,            # Src Port: 1234
      0x00, 0x35,            # Dst Port: 53 (DNS)
      0x00, 0x0c,            # Length: 12 bytes
      0x12, 0x34,            # Checksum
      0xaa, 0xbb, 0xcc, 0xdd # 4 bytes UDP payload
    ]

    res = dissector.dissect(data, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::Udp)
    res.fields["udp.src_port"].should eq(1234_u16)
    res.fields["udp.dst_port"].should eq(53_u16)
    res.fields["udp.length"].should eq(12_u32)
    res.payload_length.should eq(4_u32)
    res.next_protocol.should eq(Filament::Dissect::Protocol::Dns)
  end
end

describe Filament::Dissect::Layer4::TcpDissector do
  dissector = Filament::Dissect::Layer4::TcpDissector.new

  it "dissects TCP segment with SYN and MSS option" do
    data = Bytes[
      0xcc, 0x12,             # Src Port: 52242
      0x01, 0xbb,             # Dst Port: 443 (HTTPS)
      0x10, 0x20, 0x30, 0x40, # Seq: 0x10203040
      0x00, 0x00, 0x00, 0x00, # Ack: 0
      0x80, 0x02,             # Data Offset: 8 words (32 bytes), Flags: SYN
      0xfa, 0xf0,             # Window Size: 64240
      0x12, 0x34,             # Checksum
      0x00, 0x00,             # Urgent Pointer
      # Options: 12 bytes
      0x02, 0x04, 0x05, 0xb4, # MSS: 1460 (0x05b4)
      0x01,                   # NOP
      0x03, 0x03, 0x07,       # Window Scale: 7
      0x04, 0x02,             # SACK Permitted
      0x00, 0x00              # EOL / Padding
    ]

    res = dissector.dissect(data, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::Tcp)
    res.fields["tcp.src_port"].should eq(52242_u16)
    res.fields["tcp.dst_port"].should eq(443_u16)
    res.fields["tcp.seq"].should eq(0x10203040_u32)
    res.fields["tcp.flags.syn"].should eq(true)
    res.fields["tcp.flags.ack"].should eq(false)
    res.fields["tcp.window_size"].should eq(64240_u16)
    res.fields["tcp.options.mss"].should eq(1460_u32)
    res.fields["tcp.options.window_scale"].should eq(7_u32)
    res.fields["tcp.options.sack_permitted"].should eq(true)
    res.next_protocol.should eq(Filament::Dissect::Protocol::Tls)
  end
end

describe Filament::Dissect::Layer4::TcpSeq do
  it "correctly handles 32-bit sequence number wrap-around arithmetic" do
    seq_a = 0xFFFFFFF0_u32
    seq_b = 0x00000010_u32

    # In modular space, seq_b is after seq_a across the wrap boundary
    Filament::Dissect::Layer4::TcpSeq.lt?(seq_a, seq_b).should be_true
    Filament::Dissect::Layer4::TcpSeq.gt?(seq_b, seq_a).should be_true
    Filament::Dissect::Layer4::TcpSeq.diff(seq_b, seq_a).should eq(32_i64)
  end
end

describe Filament::Dissect::Layer4::TcpStreamReassembler do
  it "reassembles out-of-order and overlapping TCP streams" do
    reassembler = Filament::Dissect::Layer4::TcpStreamReassembler.new

    # Segment 1 arrives at seq 100 with payload "Hello " (len 6) -> next expected is 106
    chunk1 = reassembler.push(100_u32, "Hello ".to_slice)
    String.new(chunk1).should eq("Hello ")

    # Segment 3 arrives out of order at seq 113 with payload "world!" (len 6)
    chunk3 = reassembler.push(113_u32, "world!".to_slice)
    chunk3.should be_empty # Buffered waiting for 106..113

    # Segment 2 arrives at seq 106 with payload "brave " (len 6) -> 106 to 112
    # Still a 1-byte hole at seq 112!
    chunk2 = reassembler.push(106_u32, "brave ".to_slice)
    String.new(chunk2).should eq("brave ")

    # Bridge packet arrives at seq 112 with payload " " (len 1)
    # This should close the hole and immediately drain both space and buffered "world!"
    chunk_bridge = reassembler.push(112_u32, " ".to_slice)
    String.new(chunk_bridge).should eq(" world!")
  end
end
