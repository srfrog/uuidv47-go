# uuidv47-go

[![Go Reference](https://pkg.go.dev/badge/github.com/srfrog/uuidv47-go.svg)](https://pkg.go.dev/github.com/srfrog/uuidv47-go) [![Go Report Card](https://goreportcard.com/badge/github.com/srfrog/uuidv47-go)](https://goreportcard.com/report/github.com/srfrog/uuidv47-go) ![go-ci](https://github.com/srfrog/uuidv47-go/actions/workflows/go-ci.yml/badge.svg) ![codeql](https://github.com/srfrog/uuidv47-go/actions/workflows/codeql-analysis.yml/badge.svg)

**UUIDv7-in / UUIDv4-out** - SipHash-masked timestamp transformation

`uuidv47-go` lets you store sortable UUIDv7 in your database while emitting a UUIDv4-looking façade at your API boundary. It XOR-masks *only* the UUIDv7 timestamp field with a keyed SipHash-2-4 stream derived from the UUID's own random bits. The mapping is deterministic and exactly invertible.

- **Pure Go** zero dependencies
- **Deterministic, invertible** mapping (exact round-trip)
- **RFC-compatible** version/variant bits (v7 in DB, v4 on the wire)
- **Key-recovery resistant** (SipHash-2-4, 128-bit key)
- **Zero allocations** for encode/decode operations
- **Fully tested** with comprehensive test suite
- **High performance** (~67 ns/op for encode+decode on Apple M3)

This is a Go port of the original [UUIDv47 C implementation](https://github.com/stateless-me/uuidv47).

---

## Why

- **DB-friendly**: UUIDv7 is time-ordered for better index locality & pagination
- **Externally neutral**: The façade hides timing patterns and looks like v4 to clients
- **Secret safety**: Uses a PRF (SipHash-2-4). Non-crypto hashes are not suitable when the key must not leak

---

## Installation

```bash
go get github.com/srfrog/uuidv47-go
```

---

## Quick Start

See the complete [example](example_test.go) for typical usage patterns.

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/srfrog/uuidv47-go"
)

func main() {
    // Define your secret key (128 bits)
    key := uuid47.Key{
        K0: 0x0123456789abcdef,
        K1: 0xfedcba9876543210,
    }
    
    // Parse a UUIDv7 (e.g., from your database)
    s := "018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f"
    idV7, err := uuid47.Parse(s)
    if err != nil {
        log.Fatal(err)
    }
    
    // Encode to UUIDv4 façade (for API output)
    facade := uuid47.Encode(idV7, key)
    
    // Decode back to UUIDv7 (when receiving from API)
    back := uuid47.Decode(facade, key)
    
    fmt.Printf("v7 (DB) : %s\n", idV7.String())
    fmt.Printf("v4 (API): %s\n", facade.String())
    fmt.Printf("back    : %s\n", back.String())
    
    // Verify round-trip
    if idV7.Equal(back) {
        fmt.Println("Round-trip: success")
    }
}
```

**Output:**
```
v7 (DB) : 018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f
v4 (API): 2463c780-7fca-4def-8c3f-7b1a2c4d5e6f
back    : 018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f
Round-trip: success
```

---

## API Reference

### Types

```go
// UUID represents a 128-bit UUID
type UUID [16]byte

// Key represents a SipHash 128-bit key for UUIDv47
type Key struct {
    K0, K1 uint64
}
```

### Core Transformation Functions

```go
// Encode encodes a UUIDv7 as a UUIDv4 façade
func Encode(v7 UUID, key Key) UUID

// Decode decodes a UUIDv4 façade back to UUIDv7
func Decode(v4facade UUID, key Key) UUID
```

### Parsing and Formatting

```go
// Parse parses a UUID string in canonical format (8-4-4-4-12)
func Parse(s string) (UUID, error)

// String returns the UUID in canonical format
func (u *UUID) String() string
```

### UUID Inspection

```go
// Version returns the UUID version (4 or 7)
func (u *UUID) Version() int
```

### UUID Manipulation

```go
// SetVersion sets the UUID version
func (u *UUID) SetVersion(ver int)

// SetVariantRFC4122 sets the RFC4122 variant bits (10xxxxxx)
func (u *UUID) SetVariantRFC4122()
```

### Utility Methods

```go
// Bytes returns the UUID as a byte slice
func (u *UUID) Bytes() []byte

// SetBytes sets the UUID from a byte slice
func (u *UUID) SetBytes(b []byte) error

// IsZero returns true if the UUID is all zeros
func (u *UUID) IsZero() bool

// Equal returns true if two UUIDs are equal
func (u *UUID) Equal(other UUID) bool
```

### Text Marshaling

```go
// MarshalText implements encoding.TextMarshaler
func (u UUID) MarshalText() ([]byte, error)

// UnmarshalText implements encoding.TextUnmarshaler
func (u *UUID) UnmarshalText(text []byte) error
```

---

## Specification

### UUIDv7 Bit Layout

- **ts_ms_be**: 48-bit big-endian timestamp (milliseconds)
- **ver**: high nibble of byte 6 = `0x7` (v7) or `0x4` (façade)
- **rand_a**: 12 random bits
- **var**: RFC variant (`0b10`)
- **rand_b**: 62 random bits

### Façade Mapping

- **Encode**: `ts48 ^ mask48(R)`, then set version = 4
- **Decode**: `encTS ^ mask48(R)`, then set version = 7
- Random bits remain unchanged

### SipHash Message

10 bytes derived from the v7 random field:
```
msg[0] = (byte6 & 0x0F)
msg[1] = byte7
msg[2] = (byte8 & 0x3F)
msg[3..9] = bytes9..15
```

### Invertibility

The mask is XOR with a keyed PRF and is perfectly invertible when the key is known.

### Collision Analysis

Mapping is injective; collisions reduce to duplicate randoms within the same millisecond.

If two IDs have the same randoms but different timestamps, XORing the façade IDs will reveal the XOR of the timestamps (the mask cancels out). This does not reveal the key, only an upper bound on the duration between ID generation. For a 1% chance of finding 2 matching randoms, ~20 billion IDs would need to be generated using the birthday problem approximation.

---

## Security Model

- **Goal**: Secret key unrecoverable even with chosen inputs
- **Achieved**: SipHash-2-4 is a keyed PRF (Pseudorandom Function)
- **Keys**: 128-bit (K0 and K1 are each 64 bits)
- **Key Generation**: Use cryptographically secure random generation
- **Key Derivation**: Recommend deriving via HKDF from a master secret
- **Key Storage**: Use KMS (AWS KMS, GCP KMS, HashiCorp Vault, etc.)
- **Rotation**: Store a small key ID alongside UUIDs (out-of-band)

### Key Management Best Practices

**Generating Keys:**
```go
import "crypto/rand"

// Generate a new random key (do this ONCE, store securely)
func GenerateKey() (Key, error) {
    var key Key
    var buf [16]byte
    if _, err := rand.Read(buf[:]); err != nil {
        return Key{}, err
    }
    key.K0 = binary.BigEndian.Uint64(buf[0:8])
    key.K1 = binary.BigEndian.Uint64(buf[8:16])
    return key, nil
}
```

**Deriving Keys with HKDF (Recommended):**
```go
import (
    "crypto/sha256"
    "golang.org/x/crypto/hkdf"
    "io"
)

// Derive a key from a master secret using HKDF
func DeriveKey(masterSecret []byte, info string) (Key, error) {
    hkdf := hkdf.New(sha256.New, masterSecret, nil, []byte(info))
    var buf [16]byte
    if _, err := io.ReadFull(hkdf, buf[:]); err != nil {
        return Key{}, err
    }
    return Key{
        K0: binary.BigEndian.Uint64(buf[0:8]),
        K1: binary.BigEndian.Uint64(buf[8:16]),
    }, nil
}
```

**DO NOT:**
- Hardcode keys in source code (example values are for demo only!)
- Derive keys from UUIDs, timestamps, or other predictable values
- Use the same key across different environments (dev/staging/prod)
- Share keys between different applications

**DO:**
- Store keys in a KMS or secure vault
- Rotate keys periodically
- Use different keys per environment
- Log key usage for audit purposes

---

## Performance

Benchmarks on Apple M3 (go test -bench=. -benchmem):

```
BenchmarkEncodeDecodePair-8    17324892    67.39 ns/op    0 B/op    0 allocs/op
BenchmarkEncode-8              53727633    22.40 ns/op    0 B/op    0 allocs/op
BenchmarkDecode-8              53545231    22.42 ns/op    0 B/op    0 allocs/op
BenchmarkSipHash24_10B-8       73857516    16.33 ns/op    0 B/op    0 allocs/op
BenchmarkUUIDParse-8           23971672    49.67 ns/op    0 B/op    0 allocs/op
BenchmarkUUIDString-8          20502306    57.01 ns/op   48 B/op    1 allocs/op
```

**What it measures:**
- `EncodeDecodePair`: Full v7 to façade to v7 round-trip
- `Encode`: UUIDv7 → UUIDv4 façade transformation
- `Decode`: UUIDv4 façade to UUIDv7 transformation
- `SipHash24_10B`: SipHash-2-4 on 10-byte message
- `UUIDParse`: String parsing
- `UUIDString`: String formatting

**Key highlights:**
- Zero allocations for all cryptographic operations
- ~67 ns for complete encode+decode roundtrip
- ~16 ns for SipHash-2-4 hash computation

---

## Integration Tips

### General Recommendations

- **Store only the UUIDv7**, not the façade ID
- **Manage the secret** through a Key Management Service (KMS)
- **Derive keys** using HKDF from a master secret

### Frontend/Client-Facing Entities

Use **UUIDv47** with a B-Tree index. Users aren't expected to persist this ID and can tolerate cache resets. Secure the secret with an HSM and inject it safely into the process.

### External Service-Facing Entities

If the service is **secure** (e.g., financial), provide **UUIDv7**.

If the service is **not secure**, provide a **secondary ID of type UUIDv4** with a hash index.

If the master key leaks, it's almost certain your consumer data and systems have leaked as well, which is ultimately a **legal problem**, not a technical one. Data leaks will cause far greater issues than the compromise of an ID master key, which can be rotated safely since only the frontend depends on it.

### Example with JSON API

```go
type User struct {
    ID uuid47.UUID `json:"id"`
    Name string       `json:"name"`
}

func (u *User) MarshalJSON() ([]byte, error) {
    type Alias User
    facade := uuid47.Encode(u.ID, appKey)
    return json.Marshal(&struct {
        ID string `json:"id"`
        *Alias
    }{
        ID: facade.String(),
        Alias: (*Alias)(u),
    })
}
```

---

## FAQ

### Key Management

**Q: How do I generate the K0 and K1 key values?**  
A: Use cryptographically secure random generation (see [Security Model](#security-model) section). Never hardcode keys—the example values like `0x0123456789abcdef` are for demonstration only. In production:
1. Generate once using `crypto/rand`
2. Store in KMS/vault (AWS KMS, GCP KMS, HashiCorp Vault)
3. Load at application startup
4. Or derive from a master secret using HKDF

**Q: What about key rotation?**  
A: Store a key version ID (1-2 bytes) alongside each UUID. When decoding, use the appropriate key version. This allows gradual migration without breaking existing façades.

**Q: Can I use environment variables for keys?**  
A: Only for development/testing. For production, use a proper KMS. If you must use env vars, ensure:
- Variables are encrypted at rest
- Access is logged and restricted
- Keys are rotated regularly
- Never commit to version control

### Security

**Q: Why SipHash-2-4 specifically? What about other hash functions?**  
A: SipHash-2-4 is chosen because it's a **keyed PRF (Pseudorandom Function)**, not just a hash:

**Why not alternatives:**
- **xxHash/xxHash3 with secret**: Not cryptographically designed as a PRF. Keys can potentially leak through timing attacks or chosen-input attacks.
- **MD5/SHA-256 with secret**: Not keyed PRFs; vulnerable to length extension attacks. Using HMAC adds overhead.
- **AES**: More overhead (~100-200 ns vs ~16 ns for SipHash), requires more careful implementation.
- **ChaCha20**: Designed for encryption, not as a PRF for this use case. More overhead.

**Why SipHash-2-4:**
- [x] **Designed as a keyed PRF** - specifically for hash table security
- [x] **Fast** - ~16 ns/op on modern hardware (10-byte input)
- [x] **Small** - Minimal code footprint, easy to audit
- [x] **Proven** - Used in hash tables for Python, Ruby, Rust, etc.
- [x] **Key-recovery resistant** - 128-bit key, designed against chosen-input attacks
- [x] **No timing attacks** - Constant-time implementation possible

**SipHash-2-4 vs SipHash-1-3:**
- SipHash-2-4 (used here): 2 compression rounds, 4 finalization rounds → more secure
- SipHash-1-3: Faster but slightly less security margin
- We use 2-4 for maximum security since performance is already excellent

**Q: Is the façade indistinguishable from UUIDv4?**  
A: Version/variant bits are v4-compliant; variable bits are uniformly distributed under the PRF assumption. To an external observer without the key, the façade appears as a standard UUIDv4.

**Q: What if the key leaks?**  
A: An attacker with the key can:
- Decode façades back to UUIDv7 (revealing timestamps)
- Determine which UUIDs came from the same time period

They **cannot**:
- Forge valid UUIDs without controlling the random generator
- Break the underlying UUIDv7 generation

**Mitigation**: If a key leak is detected, immediately rotate keys. Store a key version with each UUID so old façades remain decodable during transition.

### Compatibility

**Q: Can I use this with existing UUIDv7 libraries?**  
A: Yes! Generate UUIDv7 with any library (e.g., `google/uuid`), then use `uuidv47-go` only for the façade transformation.

**Q: How do I generate UUIDv7?**  
A: This library focuses on the transformation. Use existing Go UUIDv7 libraries like:
- [google/uuid](https://github.com/google/uuid) (supports v7)
- [gofrs/uuid](https://github.com/gofrs/uuid)

**Q: Is this compatible with the C implementation?**  
A: Yes! Same algorithm, same key format, same output. You can decode Go-encoded façades in C and vice versa.

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## License

MIT License - Copyright (c) 2025 CastleBytes https://castlebytes.com

This is a Go port of the original [UUIDv47 C implementation](https://github.com/stateless-me/uuidv47).
