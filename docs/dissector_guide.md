# Protocol Dissector Developer Guide

This guide walks developers through implementing, registering, and testing a custom protocol dissector in Filament.

---

## 1. Dissector Architecture

Protocol dissection in Filament follows a recursive descent model. Each layer in the network stack inspects the header at its assigned offset, validates boundaries, extracts structured fields into a `FieldValue` dictionary, and identifies the next layer in the protocol hierarchy.

### 1.1 Core Abstractions

Every dissector inherits from `Filament::Dissect::Dissector` (`src/filament/dissect/dissector.cr`):

```crystal
abstract class Dissector
  # Returns the unique Protocol enum variant handled by this dissector
  abstract def protocol : Protocol

  # Returns the human-readable protocol name (e.g. "DNS")
  abstract def name : String

  # Dissects payload bytes starting at offset, returning structured results
  abstract def dissect(data : Bytes, offset : UInt32) : DissectResult

  # Optional heuristic to check whether the byte stream matches this protocol
  def can_dissect?(data : Bytes, offset : UInt32) : Bool
    true
  end
end
```

### 1.2 DissectResult Structure

The `DissectResult` struct communicates dissection outcomes to the engine:

```crystal
struct DissectResult
  getter protocol : Protocol
  getter fields : Hash(String, FieldValue)
  getter payload_offset : UInt32
  getter payload_length : UInt32
  getter next_protocol : Protocol?
  getter errors : Array(String)
end
```

- `fields`: Dot-notated string keys mapped to typed `FieldValue` unions (`String | UInt8 | UInt16 | UInt32 | UInt64 | Int32 | Int64 | Float64 | Bool | Bytes`).
- `payload_offset`: The absolute offset in the packet slice where the payload for the next layer begins.
- `payload_length`: The length in bytes of the inner payload.
- `next_protocol`: An optional hint telling `DissectorRegistry` which dissector should process the inner payload next.
- `errors`: A list of non-fatal malformation errors encountered (e.g. truncated header, invalid flag combination).

---

## 2. Step-by-Step Implementation Example

Let us implement a dissector for a hypothetical protocol called **EchoProto** (a 4-byte header containing a 1-byte message type, a 1-byte status code, and a 2-byte payload length).

### Step 1: Add Protocol Enum Variant
In `src/filament/dissect/dissector.cr`, add the new protocol variant:

```crystal
enum Protocol
  Ethernet
  Ipv4
  Tcp
  Udp
  # ... existing protocols ...
  EchoProto
end
```

### Step 2: Implement the Dissector Class
Create `src/filament/dissect/layer7/echo_proto.cr`:

```crystal
require "../dissector"

module Filament
  module Dissect
    module Layer7
      class EchoProtoDissector < Dissector
        HEADER_SIZE = 4_u32

        def protocol : Protocol
          Protocol::EchoProto
        end

        def name : String
          "EchoProto"
        end

        def dissect(data : Bytes, offset : UInt32) : DissectResult
          errors = [] of String
          fields = Hash(String, FieldValue).new

          # Verify minimum length boundary
          available = data.size.to_u32 &- offset
          if available < HEADER_SIZE
            errors << "Truncated EchoProto header (need 4 bytes, got #{available})"
            return DissectResult.new(
              protocol: protocol,
              fields: fields,
              payload_offset: offset + available,
              payload_length: 0_u32,
              next_protocol: nil,
              errors: errors
            )
          end

          # Parse header fields
          msg_type = data[offset]
          status_code = data[offset + 1]
          payload_len = IO::ByteFormat::BigEndian.decode(UInt16, data[offset + 2, 2])

          fields["echo.type"] = msg_type
          fields["echo.status"] = status_code
          fields["echo.len"] = payload_len

          payload_offset = offset + HEADER_SIZE
          actual_payload_len = Math.min(payload_len.to_u32, available - HEADER_SIZE)

          DissectResult.new(
            protocol: protocol,
            fields: fields,
            payload_offset: payload_offset,
            payload_length: actual_payload_len,
            next_protocol: nil,
            errors: errors
          )
        end
      end
    end
  end
end
```

### Step 3: Register in DissectorRegistry
Register the dissector in `DissectorRegistry.instance`:

```crystal
DissectorRegistry.instance.register(
  Protocol::EchoProto,
  Filament::Dissect::Layer7::EchoProtoDissector.new
)
```

In the parent dissector (such as UDP or TCP), route port numbers or protocol signatures to `Protocol::EchoProto`:

```crystal
# Example inside UdpDissector or a custom dynamic dispatcher:
next_proto = case dst_port
when 9999_u16
  Protocol::EchoProto
else
  nil
end
```

---

## 3. Best Practices & Performance Guidelines

1. **Zero Heap Allocations in Hot Paths**:
   - Never copy packet slices or reallocate buffers during header parsing. Slice existing `Bytes` directly (`data[offset, len]`).
   - Use `IO::ByteFormat::BigEndian.decode(T, slice)` to decode primitive integers directly from memory without allocating intermediate strings or arrays.

2. **Defensive Length Checking**:
   - Always verify that `data.size >= offset + expected_header_len` before reading.
   - Guard against integer overflow by using wrapping subtraction (`&-`) or casting boundary math safely.

3. **Loop Boundaries & Pointer Traversal**:
   - When parsing variable-length TLV options or compression pointers (such as in DNS or DHCP), enforce a strict loop iteration counter (e.g. maximum 64 iterations) to prevent infinite loops from cyclic pointers.

4. **Unit Testing**:
   - Write comprehensive specs in `spec/dissect/` providing synthetic raw byte arrays covering both valid headers and malformed edge cases.
