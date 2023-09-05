require "../spec_helper"

describe Filament::Capture::BpfEvaluator do
  # Synthetic Ethernet + IPv4 + UDP packet
  # EtherType at offset 12: 0x0800
  # IP proto at offset 23: 17 (UDP)
  # IP src at offset 26: 10.0.0.1
  # IP dst at offset 30: 10.0.0.2
  # UDP src port at offset 34: 1234
  # UDP dst port at offset 36: 53
  packet_data = Bytes[
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0x08, 0x00,                         # EtherType: IPv4
    0x45, 0x00, 0x00, 0x1c,             # IPv4 IHL=5 (20 bytes)
    0x00, 0x01, 0x00, 0x00,
    0x40, 0x11, 0x00, 0x00,             # Proto = 17 (UDP)
    0x0a, 0x00, 0x00, 0x01,             # 10.0.0.1
    0x0a, 0x00, 0x00, 0x02,             # 10.0.0.2
    0x04, 0xd2, 0x00, 0x35,             # Src port 1234, Dst port 53
    0x00, 0x08, 0x00, 0x00
  ]

  it "matches IPv4 filter expression" do
    prog = Filament::Capture::BpfCompiler.compile("ip")
    res = Filament::Capture::BpfEvaluator.evaluate(prog, packet_data)
    res.should be > 0_u32
  end

  it "rejects ARP filter for an IPv4 packet" do
    prog = Filament::Capture::BpfCompiler.compile("arp")
    res = Filament::Capture::BpfEvaluator.evaluate(prog, packet_data)
    res.should eq(0_u32)
  end

  it "matches UDP protocol filter" do
    prog = Filament::Capture::BpfCompiler.compile("udp")
    res = Filament::Capture::BpfEvaluator.evaluate(prog, packet_data)
    res.should be > 0_u32
  end

  it "rejects TCP protocol filter for a UDP packet" do
    prog = Filament::Capture::BpfCompiler.compile("tcp")
    res = Filament::Capture::BpfEvaluator.evaluate(prog, packet_data)
    res.should eq(0_u32)
  end

  it "matches port filter matching destination port 53" do
    prog = Filament::Capture::BpfCompiler.compile("port 53")
    res = Filament::Capture::BpfEvaluator.evaluate(prog, packet_data)
    res.should be > 0_u32
  end

  it "matches host filter" do
    prog = Filament::Capture::BpfCompiler.compile("host 10.0.0.1")
    res = Filament::Capture::BpfEvaluator.evaluate(prog, packet_data)
    res.should be > 0_u32

    prog_other = Filament::Capture::BpfCompiler.compile("host 192.168.1.1")
    res_other = Filament::Capture::BpfEvaluator.evaluate(prog_other, packet_data)
    res_other.should eq(0_u32)
  end
end
