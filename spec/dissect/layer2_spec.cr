require "../spec_helper"
require "../../src/filament/dissect/layer2/ethernet"
require "../../src/filament/dissect/layer2/arp"
require "../../src/filament/dissect/layer2/sll"
require "../../src/filament/dissect/layer2/ppp"

describe Filament::Dissect::Layer2::EthernetDissector do
  dissector = Filament::Dissect::Layer2::EthernetDissector.new

  it "dissects a standard Ethernet II frame" do
    data = Bytes[
      0x00, 0x50, 0x56, 0xc0, 0x00, 0x08, # Dst MAC
      0x00, 0x0c, 0x29, 0x4a, 0x8b, 0x1f, # Src MAC
      0x08, 0x00,                         # EtherType: IPv4
      0x45, 0x00, 0x00, 0x28              # IP payload bytes...
    ]

    res = dissector.dissect(data, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::Ethernet)
    res.fields["eth.dst"].should eq("00:50:56:c0:00:08")
    res.fields["eth.src"].should eq("00:0c:29:4a:8b:1f")
    res.fields["eth.dst.multicast"].should eq(false)
    res.fields["eth.dst.broadcast"].should eq(false)
    res.fields["eth.type"].should eq(0x0800_u16)
    res.next_protocol.should eq(Filament::Dissect::Protocol::IPv4)
    res.payload_offset.should eq(14_u32)
  end

  it "detects broadcast MAC destination" do
    data = Bytes[
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x08, 0x06, # ARP
      0x00, 0x01,
    ]

    res = dissector.dissect(data, 0_u32)
    res.fields["eth.dst.broadcast"].should eq(true)
    res.fields["eth.dst.multicast"].should eq(true) # Broadcast has LSB set
    res.next_protocol.should eq(Filament::Dissect::Protocol::Arp)
  end

  it "dissects IEEE 802.1Q tagged VLAN frame" do
    data = Bytes[
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
      0x81, 0x00, # 802.1Q Tag
      0xa0, 0x64, # PCP=5, DEI=0, VID=100 (0x064)
      0x08, 0x00, # Inner EtherType: IPv4
      0x45, 0x00,
    ]

    res = dissector.dissect(data, 0_u32)
    res.fields["vlan.id"].should eq(100_u32)
    res.fields["vlan.pcp"].should eq(5_u8)
    res.fields["vlan.dei"].should eq(false)
    res.next_protocol.should eq(Filament::Dissect::Protocol::IPv4)
    res.payload_offset.should eq(18_u32)
  end
end

describe Filament::Dissect::Layer2::ArpDissector do
  dissector = Filament::Dissect::Layer2::ArpDissector.new

  it "dissects an ARP request" do
    # 28 bytes ARP packet
    data = Bytes[
      0x00, 0x01,                         # HTYPE: Ethernet
      0x08, 0x00,                         # PTYPE: IPv4
      0x06, 0x04,                         # HLEN=6, PLEN=4
      0x00, 0x01,                         # Opcode: Request
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, # SHA
      0xc0, 0xa8, 0x01, 0x0a,             # SPA: 192.168.1.10
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # THA
      0xc0, 0xa8, 0x01, 0x01              # TPA: 192.168.1.1
    ]

    res = dissector.dissect(data, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::Arp)
    res.fields["arp.operation_name"].should eq("Request")
    res.fields["arp.src_mac"].should eq("00:11:22:33:44:55")
    res.fields["arp.src_ip"].should eq("192.168.1.10")
    res.fields["arp.dst_ip"].should eq("192.168.1.1")
    res.fields["arp.is_gratuitous"].should eq(false)
    res.fields["arp.is_probe"].should eq(false)
  end

  it "identifies gratuitous ARP announcement" do
    data = Bytes[
      0x00, 0x01, 0x08, 0x00,
      0x06, 0x04,
      0x00, 0x02,                         # Reply
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, # SHA
      0x0a, 0x00, 0x00, 0x05,             # SPA: 10.0.0.5
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, # THA
      0x0a, 0x00, 0x00, 0x05              # TPA: 10.0.0.5
    ]

    res = dissector.dissect(data, 0_u32)
    res.fields["arp.is_gratuitous"].should eq(true)
  end
end

describe Filament::Dissect::Layer2::SllDissector do
  dissector = Filament::Dissect::Layer2::SllDissector.new

  it "dissects Linux cooked capture frame" do
    data = Bytes[
      0x00, 0x00,                                     # Packet type: Host (0)
      0x00, 0x01,                                     # ARPHRD: Ethernet (1)
      0x00, 0x06,                                     # Address length: 6
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x00, # 8-byte address
      0x08, 0x00,                                     # Protocol: IPv4
      0x45, 0x00                                      # Payload
    ]

    res = dissector.dissect(data, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::Sll)
    res.next_protocol.should eq(Filament::Dissect::Protocol::IPv4)
    res.payload_offset.should eq(16_u32)
  end
end
