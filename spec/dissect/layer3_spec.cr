require "../spec_helper"
require "../../src/filament/dissect/layer3/ipv4"
require "../../src/filament/dissect/layer3/ipv4_reassembler"
require "../../src/filament/dissect/layer3/ipv6"
require "../../src/filament/dissect/layer3/icmp"
require "../../src/filament/dissect/layer3/icmpv6"

describe Filament::Dissect::Layer3::IPv4Dissector do
  dissector = Filament::Dissect::Layer3::IPv4Dissector.new

  it "dissects standard IPv4 header and validates checksum" do
    data = Bytes[
      0x45, 0x00, 0x00, 0x28, # IHL=5, Total Len=40
      0x1c, 0x46, 0x40, 0x00, # ID=7238, DF=1, Frag=0
      0x40, 0x06, 0x4c, 0x6e, # TTL=64, Proto=TCP(6), Checksum=0x4c6e
      0xc0, 0xa8, 0x01, 0x64, # 192.168.1.100
      0x08, 0x08, 0x08, 0x08, # 8.8.8.8
      0x00, 0x50, 0x00, 0x50  # Payload start
    ]

    res = dissector.dissect(data, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::IPv4)
    res.fields["ip.version"].should eq(4_u32)
    res.fields["ip.hdr_len"].should eq(20_u32)
    res.fields["ip.total_len"].should eq(40_u32)
    res.fields["ip.id"].should eq(7238_u32)
    res.fields["ip.flags.df"].should eq(true)
    res.fields["ip.flags.mf"].should eq(false)
    res.fields["ip.ttl"].should eq(64_u32)
    res.fields["ip.proto"].should eq(6_u32)
    res.fields["ip.src"].should eq("192.168.1.100")
    res.fields["ip.dst"].should eq("8.8.8.8")
    res.fields["ip.checksum_valid"].should eq(true)
    res.next_protocol.should eq(Filament::Dissect::Protocol::Tcp)
  end
end

describe Filament::Dissect::Layer3::IPv4FragmentReassembler do
  it "reassembles out-of-order IP fragments" do
    reassembler = Filament::Dissect::Layer3::IPv4FragmentReassembler.new
    now = Time.utc

    frag1_data = Bytes[0x01, 0x02, 0x03, 0x04]
    frag2_data = Bytes[0x05, 0x06, 0x07, 0x08]

    # Receive fragment 2 first: offset=4, MF=false
    res1 = reassembler.process(
      "10.0.0.1", "10.0.0.2", 1234_u16, 17_u8,
      4_u16, false, frag2_data, now
    )
    res1.should be_nil

    # Receive fragment 1 second: offset=0, MF=true
    res2 = reassembler.process(
      "10.0.0.1", "10.0.0.2", 1234_u16, 17_u8,
      0_u16, true, frag1_data, now
    )

    res2.should_not be_nil
    if full = res2
      full.should eq(Bytes[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    end
  end
end

describe Filament::Dissect::Layer3::IPv6Dissector do
  dissector = Filament::Dissect::Layer3::IPv6Dissector.new

  it "dissects IPv6 header with canonical RFC 5952 zero compression" do
    data = Bytes[
      0x60, 0x00, 0x00, 0x00, # Version 6, TC=0, Flow=0
      0x00, 0x20, 0x06, 0x40, # Payload=32, Next=TCP(6), Hop=64
      # 2001:0db8:0000:0000:0000:0000:0000:0001 -> 2001:db8::1
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
      # 2607:f8b0:4005:0805:0000:0000:0000:200e -> 2607:f8b0:4005:805::200e
      0x26, 0x07, 0xf8, 0xb0, 0x40, 0x05, 0x08, 0x05,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0e
    ]

    res = dissector.dissect(data, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::IPv6)
    res.fields["ipv6.src"].should eq("2001:db8::1")
    res.fields["ipv6.dst"].should eq("2607:f8b0:4005:805::200e")
    res.next_protocol.should eq(Filament::Dissect::Protocol::Tcp)
  end
end

describe Filament::Dissect::Layer3::IcmpDissector do
  dissector = Filament::Dissect::Layer3::IcmpDissector.new

  it "dissects ICMP Echo Request" do
    data = Bytes[
      0x08, 0x00, 0x21, 0x04, # Type=8, Code=0, Checksum=0x2104
      0x12, 0x34, 0x00, 0x01, # Ident=0x1234, Seq=1
      0x61, 0x62, 0x63, 0x64  # Data "abcd"
    ]

    res = dissector.dissect(data, 0_u32)
    res.fields["icmp.type"].should eq(8_u32)
    res.fields["icmp.ident"].should eq(0x1234_u32)
    res.fields["icmp.seq"].should eq(1_u32)
    res.fields["icmp.type_name"].should eq("Echo (ping) request")
    res.fields["icmp.checksum_valid"].should eq(true)
  end
end
