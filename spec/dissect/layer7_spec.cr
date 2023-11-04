require "../spec_helper"
require "../../src/filament/dissect/layer7/dns"
require "../../src/filament/dissect/layer7/http"
require "../../src/filament/dissect/layer7/tls"
require "../../src/filament/dissect/layer7/dhcp"
require "../../src/filament/dissect/layer7/ntp"
require "../../src/filament/dissect/layer7/websocket"

describe Filament::Dissect::Layer7::DnsDissector do
  dissector = Filament::Dissect::Layer7::DnsDissector.new

  it "dissects standard DNS Query for example.com" do
    # DNS Query: ID=0x1234, RD=1, QDCOUNT=1, "example.com", Type A
    data = Bytes[
      0x12, 0x34,                         # Transaction ID
      0x01, 0x00,                         # Flags: Standard Query, RD=1
      0x00, 0x01,                         # QDCOUNT = 1
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # AN, NS, AR count = 0
      # Question: 7 "example" 3 "com" 0
      0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
      0x03, 0x63, 0x6f, 0x6d,
      0x00,
      0x00, 0x01,                         # QTYPE: A (1)
      0x00, 0x01                          # QCLASS: IN (1)
    ]

    res = dissector.dissect(data, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::Dns)
    res.fields["dns.tx_id"].should eq(0x1234_u32)
    res.fields["dns.is_response"].should eq(false)
    res.fields["dns.rd"].should eq(true)
    res.fields["dns.qname"].should eq("example.com")
    res.fields["dns.qtype"].should eq("A")
  end

  it "resolves compressed domain name pointer in DNS Answer" do
    # DNS Response: ID=0x5678, QR=1, QD=1, AN=1, Question "foo.com", Answer ptr to foo.com -> 93.184.216.34
    data = Bytes[
      0x56, 0x78,
      0x81, 0x80,                         # Response, No error
      0x00, 0x01, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x00,
      # Question: 3 "foo" 3 "com" 0 at offset 12
      0x03, 0x66, 0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00,
      0x00, 0x01, 0x00, 0x01,
      # Answer: Name is pointer 0xC00C (offset 12)
      0xc0, 0x0c,
      0x00, 0x01, 0x00, 0x01,             # Type A, Class IN
      0x00, 0x00, 0x01, 0x2c,             # TTL: 300
      0x00, 0x04,                         # RDLENGTH: 4
      0x5d, 0xb8, 0xd8, 0x22              # 93.184.216.34
    ]

    res = dissector.dissect(data, 0_u32)
    res.fields["dns.is_response"].should eq(true)
    res.fields["dns.answers"].should eq("93.184.216.34")
  end
end

describe Filament::Dissect::Layer7::HttpDissector do
  dissector = Filament::Dissect::Layer7::HttpDissector.new

  it "dissects HTTP GET request and headers" do
    raw = "GET /api/v1/status HTTP/1.1\r\n" \
          "Host: example.internal\r\n" \
          "User-Agent: curl/8.4.0\r\n" \
          "Accept: */*\r\n\r\n"

    res = dissector.dissect(raw.to_slice, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::Http)
    res.fields["http.method"].should eq("GET")
    res.fields["http.uri"].should eq("/api/v1/status")
    res.fields["http.version"].should eq("HTTP/1.1")
    res.fields["http.host"].should eq("example.internal")
    res.fields["http.user_agent"].should eq("curl/8.4.0")
  end
end

describe Filament::Dissect::Layer7::TlsDissector do
  dissector = Filament::Dissect::Layer7::TlsDissector.new

  it "dissects TLS ClientHello with SNI" do
    # Craft minimal TLS 1.2 ClientHello with SNI "test.com"
    sni = "test.com"
    sni_bytes = sni.to_slice
    name_len = sni_bytes.size

    io = IO::Memory.new
    # Record Header: ContentType=22 (Handshake), Version=0x0301, Length
    io.write_byte(22_u8)
    io.write_bytes(0x0301_u16, IO::ByteFormat::BigEndian)

    # Handshake payload
    handshake_io = IO::Memory.new
    handshake_io.write_byte(1_u8) # ClientHello
    # Length placeholder (3 bytes)
    handshake_io.write(Bytes[0x00, 0x00, 0x00])

    client_body = IO::Memory.new
    client_body.write_bytes(0x0303_u16, IO::ByteFormat::BigEndian) # Client Version TLS 1.2
    client_body.write(Bytes.new(32, 0_u8))                         # Random
    client_body.write_byte(0_u8)                                   # Session ID len 0
    client_body.write_bytes(2_u16, IO::ByteFormat::BigEndian)      # Cipher suites len 2
    client_body.write_bytes(0x1301_u16, IO::ByteFormat::BigEndian) # TLS_AES_128_GCM_SHA256
    client_body.write_byte(1_u8)                                   # Compression methods len 1
    client_body.write_byte(0_u8)                                   # null compression

    # Extensions: SNI extension
    ext_body = IO::Memory.new
    # SNI extension header: type=0, len
    ext_body.write_bytes(0_u16, IO::ByteFormat::BigEndian)
    ext_body.write_bytes((5 + name_len).to_u16, IO::ByteFormat::BigEndian)
    # ServerNameList: list_len, name_type=0, name_len, name
    ext_body.write_bytes((3 + name_len).to_u16, IO::ByteFormat::BigEndian)
    ext_body.write_byte(0_u8)
    ext_body.write_bytes(name_len.to_u16, IO::ByteFormat::BigEndian)
    ext_body.write(sni_bytes)

    # Extensions total length + body
    client_body.write_bytes(ext_body.size.to_u16, IO::ByteFormat::BigEndian)
    client_body.write(ext_body.to_slice)

    # Write length into handshake header
    handshake_slice = client_body.to_slice
    len_bytes = Bytes[
      ((handshake_slice.size >> 16) & 0xFF).to_u8,
      ((handshake_slice.size >> 8) & 0xFF).to_u8,
      (handshake_slice.size & 0xFF).to_u8
    ]
    handshake_io.pos = 1
    handshake_io.write(len_bytes)
    handshake_io.pos = 4
    handshake_io.write(handshake_slice)

    total_handshake = handshake_io.to_slice
    io.write_bytes(total_handshake.size.to_u16, IO::ByteFormat::BigEndian)
    io.write(total_handshake)

    res = dissector.dissect(io.to_slice, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::Tls)
    res.fields["tls.handshake_name"].should eq("Client Hello")
    res.fields["tls.sni"].should eq("test.com")
  end
end

describe Filament::Dissect::Layer7::WebSocketDissector do
  dissector = Filament::Dissect::Layer7::WebSocketDissector.new

  it "unmasks masked text payload from client" do
    # FIN=1, Opcode=1 (Text) -> 0x81
    # Mask=1, Len=5 -> 0x85
    # Mask key: 0x37, 0xfa, 0x21, 0x3d
    # Masked "Hello": 'H'^0x37, 'e'^0xfa, 'l'^0x21, 'l'^0x3d, 'o'^0x37
    mask_key = Bytes[0x37, 0xfa, 0x21, 0x3d]
    plain = "Hello".to_slice
    masked = Bytes.new(5)
    5.times { |i| masked[i] = plain[i] ^ mask_key[i % 4] }

    frame = Bytes[0x81, 0x85] + mask_key + masked

    res = dissector.dissect(frame, 0_u32)
    res.protocol.should eq(Filament::Dissect::Protocol::WebSocket)
    res.fields["ws.fin"].should eq(true)
    res.fields["ws.opcode_name"].should eq("Text")
    res.fields["ws.text_sample"].should eq("Hello")
  end
end
