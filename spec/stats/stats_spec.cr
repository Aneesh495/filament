require "../spec_helper"
require "../../src/filament/stats/hierarchy"
require "../../src/filament/stats/endpoints"
require "../../src/filament/stats/conversations"
require "../../src/filament/stats/io_rate"
require "../../src/filament/stats/latency"
require "../../src/filament/stats/heavy_hitters"
require "../../src/filament/dissect/layer2/ethernet"
require "../../src/filament/dissect/layer3/ipv4"
require "../../src/filament/dissect/layer4/tcp"

describe Filament::Stats::ProtocolHierarchy do
  it "accumulates protocol layers into a hierarchical tree" do
    hier = Filament::Stats::ProtocolHierarchy.new

    # Craft synthetic packet
    raw_bytes = Bytes.new(64, 0_u8)
    pkt = Filament::Capture::RawPacket.new(
      data: raw_bytes,
      timestamp: Time.utc,
      original_length: 64_u32,
      capture_length: 64_u32,
      link_type: Filament::Capture::LinkType::Ethernet
    )

    layers = [
      Filament::Dissect::DissectResult.new(Filament::Dissect::Protocol::Ethernet, 14_u32, 50_u32),
      Filament::Dissect::DissectResult.new(Filament::Dissect::Protocol::IPv4, 34_u32, 30_u32),
      Filament::Dissect::DissectResult.new(Filament::Dissect::Protocol::Tcp, 54_u32, 10_u32)
    ]
    decoded = Filament::Dissect::DecodedPacket.new(pkt, layers, 1_u64)

    hier.process(decoded)

    hier.total_packets.should eq(1_u64)
    hier.total_bytes.should eq(64_u64)

    eth_node = hier.root_nodes[Filament::Dissect::Protocol::Ethernet]
    eth_node.packet_count.should eq(1_u64)

    ip_node = eth_node.children[Filament::Dissect::Protocol::IPv4]
    ip_node.packet_count.should eq(1_u64)

    tcp_node = ip_node.children[Filament::Dissect::Protocol::Tcp]
    tcp_node.packet_count.should eq(1_u64)
  end
end

describe Filament::Stats::SpaceSavingSketch do
  it "tracks heavy hitters and dominant flows in sub-linear space" do
    sketch = Filament::Stats::SpaceSavingSketch.new(k: 5)

    # 100 packets from 10.0.0.1
    100.times { sketch.update("10.0.0.1", 1_u64) }

    # 50 packets from 10.0.0.2
    50.times { sketch.update("10.0.0.2", 1_u64) }

    # 5 packets each from 10 other hosts
    10.times do |i|
      sketch.update("192.168.1.#{i}", 5_u64)
    end

    top = sketch.top(2)
    top[0].key.should eq("10.0.0.1")
    top[0].count.should be >= 100_u64
    top[1].key.should eq("10.0.0.2")

    sketch.heavy_hitter?("10.0.0.1", phi: 0.3).should be_true
    sketch.heavy_hitter?("192.168.1.99", phi: 0.3).should be_false
  end
end

describe Filament::Stats::LatencyAnalyzer do
  it "computes percentiles and summary distributions" do
    analyzer = Filament::Stats::LatencyAnalyzer.new
    now = Time.utc

    # Add samples: 10ms, 20ms, 30ms, 40ms, 50ms, 60ms, 70ms, 80ms, 90ms, 100ms
    10.times do |i|
      analyzer.record_sample("test", (i + 1).to_f64 * 10.0, now)
    end

    analyzer.min_ms.should eq(10.0)
    analyzer.max_ms.should eq(100.0)
    analyzer.mean_ms.should eq(55.0)
    analyzer.percentile(50.0).should be >= 50.0
    analyzer.percentile(90.0).should be >= 90.0
  end
end
