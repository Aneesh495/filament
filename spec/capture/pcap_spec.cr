require "../spec_helper"

describe Filament::Capture::PcapReader do
  it "creates and round-trips a valid PCAP capture file" do
    io = IO::Memory.new

    # Write PCAP with writer
    header = Filament::Capture::PcapHeader.default(Filament::Capture::LINKTYPE_ETHERNET)
    writer = Filament::Capture::PcapWriter.new(io, header)

    # Synthetic packet: 14 bytes Ethernet + 20 bytes IP + 8 bytes UDP
    packet_data = Bytes[
      0x00, 0x11, 0x22, 0x33, 0x44, 0x55, # Dst MAC
      0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, # Src MAC
      0x08, 0x00,                         # EtherType: IPv4
      0x45, 0x00, 0x00, 0x1c,             # IPv4 header
      0x00, 0x01, 0x00, 0x00,
      0x40, 0x11, 0x00, 0x00,
      0x0a, 0x00, 0x00, 0x01,             # Src: 10.0.0.1
      0x0a, 0x00, 0x00, 0x02,             # Dst: 10.0.0.2
      0x04, 0xd2, 0x00, 0x35,             # UDP 1234 -> 53
      0x00, 0x08, 0x00, 0x00              # UDP len 8, checksum 0
    ]

    now = Time.utc(2026, 1, 1, 12, 0, 0)
    writer.write_packet(packet_data, now, packet_data.size.to_u32)

    # Rewind and read back
    io.rewind
    reader = Filament::Capture::PcapReader.new(io)

    reader.header.link_type.should eq(Filament::Capture::LINKTYPE_ETHERNET)
    packets = [] of Filament::Capture::RawPacket
    reader.each { |pkt| packets << pkt }

    packets.size.should eq(1)
    read_pkt = packets.first
    read_pkt.data.should eq(packet_data)
    read_pkt.original_length.should eq(packet_data.size)
    read_pkt.captured_length.should eq(packet_data.size)
  end

  it "rejects invalid magic numbers" do
    bad_bytes = Bytes.new(24, 0_u8)
    bad_io = IO::Memory.new(bad_bytes)
    expect_raises(Filament::Capture::InvalidMagicError) do
      Filament::Capture::PcapReader.new(bad_io)
    end
  end
end

describe Filament::Capture::RingBuffer do
  it "maintains FIFO order and reports metrics" do
    ring = Filament::Capture::RingBuffer(Int32).new(capacity: 4)
    ring.empty?.should be_true
    ring.size.should eq(0)

    ring.push(10)
    ring.push(20)
    ring.push(30)

    ring.size.should eq(3)
    ring.pop.should eq(10)
    ring.pop.should eq(20)
    ring.size.should eq(1)

    ring.push(40)
    ring.push(50)
    ring.push(60)

    # Ring should overwrite oldest when capacity exceeded
    ring.size.should be <= 4
  end
end
