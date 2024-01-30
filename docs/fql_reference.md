# Filament Query Language (FQL) Reference

Filament Query Language (FQL) is an expressive, strongly-typed domain-specific filter language designed for high-speed network packet inspection. FQL filters are compiled by Filament into bytecode and evaluated on an internal register virtual machine.

---

## 1. Syntax and Grammar

FQL expressions evaluate to a boolean result (`true` or `false`). An expression consists of protocol identifiers, field comparisons, CIDR subnet checks, membership tests, and compound boolean logic.

### 1.1 Lexical Elements

| Token Type | Examples | Description |
| :--- | :--- | :--- |
| **Protocol Keyword** | `ip`, `tcp`, `dns`, `tls`, `http` | Matches when the given protocol exists in the packet |
| **Field Identifier** | `ip.src`, `tcp.dst_port`, `dns.qname` | Canonical dot-separated protocol field path |
| **IPv4 Literal** | `192.168.1.1`, `10.0.0.1` | 32-bit dotted-quad IPv4 address |
| **IPv6 Literal** | `::1`, `fe80::1`, `2001:db8::1` | 128-bit hexadecimal IPv6 address |
| **CIDR Literal** | `10.0.0.0/8`, `192.168.0.0/16` | Network prefix for subnet membership checks |
| **Integer Literal** | `80`, `443`, `0x8000`, `65535` | Decimal or hex formatted unsigned integer |
| **String Literal** | `"example.com"`, `"GET"`, `"gzip"` | Double-quoted UTF-8 or ASCII string |
| **Boolean Literal** | `true`, `false` | Boolean constant |

---

## 2. Operators & Precedence

Operators are listed in order of evaluation precedence from highest to lowest:

| Operator | Syntax | Description | Example |
| :--- | :--- | :--- | :--- |
| **Grouping** | `( expr )` | Overrides default precedence | `(tcp or udp) and port == 53` |
| **Unary Not** | `not expr`, `!expr` | Logical negation | `not arp` |
| **Membership** | `in` | Set or subnet containment | `ip.src in 10.0.0.0/8` |
| **Relational** | `==`, `!=`, `<`, `<=`, `>`, `>=` | Value comparison | `tcp.dst_port == 443` |
| **Logical And** | `and`, `&&` | Short-circuit boolean AND | `ip.src == 10.0.0.1 and tcp` |
| **Logical Or** | `or`, `\|\|` | Short-circuit boolean OR | `tcp.port == 80 or tcp.port == 443` |

---

## 3. Supported Protocol Field Dictionary

### 3.1 Layer 2 Fields

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `eth.src` | String | Source MAC address (`aa:bb:cc:dd:ee:ff`) |
| `eth.dst` | String | Destination MAC address |
| `eth.type` | UInt16 | EtherType (e.g. `0x0800` for IPv4, `0x86dd` for IPv6) |
| `eth.vlan.id` | UInt16 | 802.1Q Virtual LAN identifier (1 to 4094) |
| `eth.vlan.priority` | UInt8 | 802.1Q Priority Code Point (0 to 7) |
| `arp.opcode` | UInt16 | ARP operation (1: Request, 2: Reply) |
| `arp.sender.mac` | String | Sender hardware address |
| `arp.sender.ip` | String | Sender protocol IPv4 address |
| `arp.target.mac` | String | Target hardware address |
| `arp.target.ip` | String | Target protocol IPv4 address |

### 3.2 Layer 3 Fields

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `ip.src` | String | Source IPv4 address |
| `ip.dst` | String | Destination IPv4 address |
| `ip.addr` | String | Matches either source or destination IPv4 address |
| `ip.proto` | UInt8 | Transport protocol number (6: TCP, 17: UDP, 1: ICMP) |
| `ip.ttl` | UInt8 | Time to Live counter |
| `ip.dscp` | UInt8 | Differentiated Services Code Point |
| `ip.ecn` | UInt8 | Explicit Congestion Notification bits |
| `ip.flags.df` | Bool | Don't Fragment flag |
| `ip.flags.mf` | Bool | More Fragments flag |
| `ip.frag_offset` | UInt16 | Fragment byte offset |
| `ipv6.src` | String | Source IPv6 address |
| `ipv6.dst` | String | Destination IPv6 address |
| `ipv6.addr` | String | Matches either source or destination IPv6 address |
| `ipv6.next_header` | UInt8 | Next header protocol number |
| `ipv6.hop_limit` | UInt8 | Hop limit counter |
| `icmp.type` | UInt8 | ICMP message type (e.g. 8: Echo Request, 0: Echo Reply) |
| `icmp.code` | UInt8 | ICMP message subtype code |

### 3.3 Layer 4 Fields

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `tcp.src_port` | UInt16 | Source TCP port |
| `tcp.dst_port` | UInt16 | Destination TCP port |
| `tcp.port` | UInt16 | Matches either source or destination TCP port |
| `tcp.seq` | UInt32 | 32-bit raw sequence number |
| `tcp.ack` | UInt32 | 32-bit acknowledgment number |
| `tcp.flags.syn` | Bool | SYN connection synchronization flag |
| `tcp.flags.ack` | Bool | ACK acknowledgment flag |
| `tcp.flags.fin` | Bool | FIN connection termination flag |
| `tcp.flags.rst` | Bool | RST connection reset flag |
| `tcp.flags.psh` | Bool | PSH push data flag |
| `tcp.flags.urg` | Bool | URG urgent pointer flag |
| `tcp.window_size` | UInt16 | Advertised receive window size |
| `udp.src_port` | UInt16 | Source UDP port |
| `udp.dst_port` | UInt16 | Destination UDP port |
| `udp.port` | UInt16 | Matches either source or destination UDP port |
| `udp.length` | UInt16 | Total UDP datagram length (header + payload) |

### 3.4 Layer 7 Fields

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `dns.id` | UInt16 | 16-bit transaction ID |
| `dns.qr` | Bool | Query (false) or Response (true) flag |
| `dns.qname` | String | Queried domain name (e.g. "api.github.com") |
| `dns.qtype` | UInt16 | Query type (1: A, 28: AAAA, 5: CNAME, 15: MX) |
| `dns.rcode` | UInt8 | Response return code (0: NoError, 3: NXDomain) |
| `http.method` | String | HTTP request method ("GET", "POST", "PUT", etc.) |
| `http.uri` | String | Request URI path |
| `http.status_code` | UInt16 | HTTP response status code (200, 404, 500) |
| `http.host` | String | HTTP Host request header |
| `http.user_agent` | String | HTTP User-Agent request header |
| `tls.version` | UInt16 | TLS record version (e.g. 0x0303 for TLS 1.2) |
| `tls.sni` | String | ClientHello Server Name Indication hostname |
| `dhcp.msg_type` | UInt8 | DHCP message type (1: Discover, 2: Offer, 3: Request, 5: Ack) |
| `ntp.stratum` | UInt8 | NTP stratum level (1: Primary reference clock) |
| `websocket.opcode` | UInt8 | WebSocket frame opcode (1: Text, 2: Binary, 8: Close) |

---

## 4. Query Examples

### 4.1 Security & Incident Response

- **Find DNS queries attempting to resolve specific domains**:
  ```fql
  dns and dns.qname == "malicious-c2.example.org"
  ```

- **Identify potential SYN flood scans targeting web ports**:
  ```fql
  tcp.flags.syn and not tcp.flags.ack and (tcp.dst_port == 80 or tcp.dst_port == 443)
  ```

- **Filter internal network traffic to external subnets**:
  ```fql
  ip.src in 192.168.0.0/16 and not (ip.dst in 192.168.0.0/16)
  ```

- **Spot cleartext HTTP basic authentication or credentials**:
  ```fql
  http and http.method == "POST" and http.uri == "/login"
  ```

- **Detect TLS traffic to specific external hostnames via SNI**:
  ```fql
  tls and tls.sni == "telemetry.internal.corp"
  ```

### 4.2 Network Troubleshooting & Diagnostics

- **Locate packets with low TTL indicating routing loops**:
  ```fql
  ip.ttl < 5
  ```

- **Find ICMP Destination Unreachable messages**:
  ```fql
  icmp.type == 3
  ```

- **Isolate TCP connection resets**:
  ```fql
  tcp.flags.rst and tcp.port == 8080
  ```

- **Monitor ARP spoofing and probe activity**:
  ```fql
  arp and arp.sender.ip == "0.0.0.0"
  ```
