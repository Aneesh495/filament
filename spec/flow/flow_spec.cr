require "../spec_helper"
require "../../src/filament/flow/key"
require "../../src/filament/flow/record"
require "../../src/filament/flow/table"
require "../../src/filament/flow/tcp_state"
require "../../src/filament/flow/tcp_anomaly"

describe Filament::Flow::FlowKey do
  it "normalizes bidirectional flow keys into a canonical identity" do
    key_fwd = Filament::Flow::FlowKey.new("192.168.1.10", "8.8.8.8", 50000_u16, 53_u16, 17_u8)
    key_rev = Filament::Flow::FlowKey.new("8.8.8.8", "192.168.1.10", 53_u16, 50000_u16, 17_u8)

    key_fwd.canonical.should eq(key_rev.canonical)

    canon, dir = key_fwd.canonical_with_direction
    canon_r, dir_r = key_rev.canonical_with_direction

    canon.should eq(canon_r)
    dir.should_not eq(dir_r)
  end
end

describe Filament::Flow::TcpConnectionTracker do
  it "tracks full three-way handshake to Established state" do
    tracker = Filament::Flow::TcpConnectionTracker.new
    tracker.state.should eq(Filament::Flow::TcpState::Closed)

    # 1. Client sends SYN
    s1 = tracker.process_segment(Filament::Flow::FlowDirection::Forward, syn: true, ack: false, fin: false, rst: false)
    s1.should eq(Filament::Flow::TcpState::SynSent)

    # 2. Server sends SYN-ACK
    s2 = tracker.process_segment(Filament::Flow::FlowDirection::Reverse, syn: true, ack: true, fin: false, rst: false)
    s2.should eq(Filament::Flow::TcpState::SynReceived)

    # 3. Client sends ACK
    s3 = tracker.process_segment(Filament::Flow::FlowDirection::Forward, syn: false, ack: true, fin: false, rst: false)
    s3.should eq(Filament::Flow::TcpState::Established)
    tracker.state.open?.should be_true
  end

  it "transitions immediately to Closed on RST" do
    tracker = Filament::Flow::TcpConnectionTracker.new
    tracker.process_segment(Filament::Flow::FlowDirection::Forward, syn: true, ack: false, fin: false, rst: false)
    s_rst = tracker.process_segment(Filament::Flow::FlowDirection::Reverse, syn: false, ack: false, fin: false, rst: true)
    s_rst.should eq(Filament::Flow::TcpState::Closed)
  end
end

describe Filament::Flow::TcpAnomalyDetector do
  it "detects retransmissions and zero window conditions" do
    detector = Filament::Flow::TcpAnomalyDetector.new
    now = Time.utc

    # 1. Initial segment seq 1000, len 500 -> highest seq 1500
    a1 = detector.inspect_segment(1000_u32, 500_u32, 0_u32, false, 65535_u16, false, false, now)
    a1.should be_nil

    # 2. Retransmission of seq 1000, len 500
    a2 = detector.inspect_segment(1000_u32, 500_u32, 0_u32, false, 65535_u16, false, false, now)
    a2.should eq(Filament::Flow::TcpAnomalyType::Retransmission)
    detector.retransmission_count.should eq(1_u32)

    # 3. Zero window packet
    a3 = detector.inspect_segment(1500_u32, 0_u32, 1500_u32, true, 0_u16, false, false, now)
    a3.should eq(Filament::Flow::TcpAnomalyType::ZeroWindow)
    detector.zero_window_count.should eq(1_u32)
  end
end
