// Copyright 2025 CastleBytes https://castlebytes.com
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package uuid47 provides UUIDv47 generation and parsing.
package uuid47

import (
	"errors"
)

// UUID version constants
const (
	Version4 = 4 // UUIDv4 (random)
	Version7 = 7 // UUIDv7 (time-ordered)
)

// Common errors
var (
	ErrInvalidLength    = errors.New("uuid47: invalid UUID string length")
	ErrInvalidFormat    = errors.New("uuid47: invalid UUID format")
	ErrInvalidHex       = errors.New("uuid47: invalid hex character")
	ErrInvalidVersion   = errors.New("uuid47: invalid UUID version")
	ErrInvalidByteSlice = errors.New("uuid47: invalid byte slice length")
)

// UUID is a 128 bit (16 byte) Universal Unique IDentifier as defined in RFC 9562.
type UUID [16]byte

// Key represents a SipHash 128-bit key for UUIDv47
type Key struct {
	K0, K1 uint64
}

// rd64le reads a 64-bit little-endian value from a byte slice
func rd64le(p []byte) uint64 {
	return uint64(p[0]) | uint64(p[1])<<8 | uint64(p[2])<<16 |
		uint64(p[3])<<24 | uint64(p[4])<<32 | uint64(p[5])<<40 |
		uint64(p[6])<<48 | uint64(p[7])<<56
}

// wr48be writes a 48-bit big-endian value to a byte slice
func wr48be(dst []byte, v48 uint64) {
	dst[0] = byte(v48 >> 40)
	dst[1] = byte(v48 >> 32)
	dst[2] = byte(v48 >> 24)
	dst[3] = byte(v48 >> 16)
	dst[4] = byte(v48 >> 8)
	dst[5] = byte(v48 >> 0)
}

// rd48be reads a 48-bit big-endian value from a byte slice
func rd48be(src []byte) uint64 {
	return uint64(src[0])<<40 | uint64(src[1])<<32 | uint64(src[2])<<24 |
		uint64(src[3])<<16 | uint64(src[4])<<8 | uint64(src[5])<<0
}

// rotl64 rotates a 64-bit value left by b bits
func rotl64(x uint64, b uint) uint64 {
	return (x << b) | (x >> (64 - b))
}

// siphash24 implements SipHash-2-4 (reference implementation)
func siphash24(in []byte, k0, k1 uint64) uint64 {
	v0 := uint64(0x736f6d6570736575) ^ k0
	v1 := uint64(0x646f72616e646f6d) ^ k1
	v2 := uint64(0x6c7967656e657261) ^ k0
	v3 := uint64(0x7465646279746573) ^ k1

	inlen := len(in)
	end := inlen &^ 7
	b := uint64(inlen) << 56

	// Process 8-byte blocks
	for i := 0; i < end; i += 8 {
		m := rd64le(in[i:])
		v3 ^= m

		// 2 compression rounds
		for range 2 {
			v0 += v1
			v2 += v3
			v1 = rotl64(v1, 13)
			v3 = rotl64(v3, 16)
			v1 ^= v0
			v3 ^= v2
			v0 = rotl64(v0, 32)
			v2 += v1
			v0 += v3
			v1 = rotl64(v1, 17)
			v3 = rotl64(v3, 21)
			v1 ^= v2
			v3 ^= v0
			v2 = rotl64(v2, 32)
		}
		v0 ^= m
	}

	// Process last 0-7 bytes
	var t uint64
	switch inlen & 7 {
	case 7:
		t |= uint64(in[end+6]) << 48
		fallthrough
	case 6:
		t |= uint64(in[end+5]) << 40
		fallthrough
	case 5:
		t |= uint64(in[end+4]) << 32
		fallthrough
	case 4:
		t |= uint64(in[end+3]) << 24
		fallthrough
	case 3:
		t |= uint64(in[end+2]) << 16
		fallthrough
	case 2:
		t |= uint64(in[end+1]) << 8
		fallthrough
	case 1:
		t |= uint64(in[end+0]) << 0
	}
	b |= t

	v3 ^= b
	for range 2 {
		v0 += v1
		v2 += v3
		v1 = rotl64(v1, 13)
		v3 = rotl64(v3, 16)
		v1 ^= v0
		v3 ^= v2
		v0 = rotl64(v0, 32)
		v2 += v1
		v0 += v3
		v1 = rotl64(v1, 17)
		v3 = rotl64(v3, 21)
		v1 ^= v2
		v3 ^= v0
		v2 = rotl64(v2, 32)
	}
	v0 ^= b

	v2 ^= 0xff
	for range 4 {
		v0 += v1
		v2 += v3
		v1 = rotl64(v1, 13)
		v3 = rotl64(v3, 16)
		v1 ^= v0
		v3 ^= v2
		v0 = rotl64(v0, 32)
		v2 += v1
		v0 += v3
		v1 = rotl64(v1, 17)
		v3 = rotl64(v3, 21)
		v1 ^= v2
		v3 ^= v0
		v2 = rotl64(v2, 32)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

// Version returns the UUID version
func (u *UUID) Version() int {
	return int(u[6]>>4) & 0x0F
}

// SetVersion sets the UUID version
func (u *UUID) SetVersion(ver int) {
	u[6] = byte((u[6] & 0x0F) | byte((ver&0x0F)<<4))
}

// SetVariantRFC4122 sets the RFC4122 variant bits (10xxxxxx)
func (u *UUID) SetVariantRFC4122() {
	u[8] = byte((u[8] & 0x3F) | 0x80)
}

// setVersion is an internal alias for backward compatibility
func (u *UUID) setVersion(ver int) {
	u.SetVersion(ver)
}

// setVariantRFC4122 is an internal alias for backward compatibility
func (u *UUID) setVariantRFC4122() {
	u.SetVariantRFC4122()
}

// buildSipInputFromV7 builds SipHash input from v7 UUID into the provided buffer.
// Takes exactly the random bits of v7 (rand_a 12b + rand_b 62b) as bytes:
// [low-nibble of b6][b7][b8&0x3F][b9..b15]
// The buffer must be at least 10 bytes.
func buildSipInputFromV7(u *UUID, msg *[10]byte) {
	msg[0] = u[6] & 0x0F
	msg[1] = u[7]
	msg[2] = u[8] & 0x3F
	msg[3] = u[9]
	msg[4] = u[10]
	msg[5] = u[11]
	msg[6] = u[12]
	msg[7] = u[13]
	msg[8] = u[14]
	msg[9] = u[15]
}

// Encode encodes a UUIDv7 as a UUIDv4 façade using the given key
func Encode(v7 UUID, key Key) UUID {
	// 1) mask = SipHash24(key, v7.random74bits) -> take low 48 bits
	var sipmsg [10]byte
	buildSipInputFromV7(&v7, &sipmsg)
	mask48 := siphash24(sipmsg[:], key.K0, key.K1) & 0x0000FFFFFFFFFFFF

	// 2) encTS = ts ^ mask
	ts48 := rd48be(v7[0:6])
	encTS := ts48 ^ mask48

	// 3) build v4 façade: write encTS, set ver=4, keep rand bytes identical, set variant
	out := v7
	wr48be(out[0:6], encTS)
	out.setVersion(4)       // façade v4
	out.setVariantRFC4122() // ensure RFC variant bits
	return out
}

// Decode decodes a UUIDv4 façade back to UUIDv7 using the given key
func Decode(v4facade UUID, key Key) UUID {
	// 1) rebuild same Sip input from façade (identical bytes)
	var sipmsg [10]byte
	buildSipInputFromV7(&v4facade, &sipmsg)
	mask48 := siphash24(sipmsg[:], key.K0, key.K1) & 0x0000FFFFFFFFFFFF

	// 2) ts = encTS ^ mask
	encTS := rd48be(v4facade[0:6])
	ts48 := encTS ^ mask48

	// 3) restore v7: write ts, set ver=7, set variant
	out := v4facade
	wr48be(out[0:6], ts48)
	out.setVersion(7)
	out.setVariantRFC4122()
	return out
}

// hexval converts a hex character to its value
func hexval(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c - 'a' + 10)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// Parse parses a UUID string in canonical format (8-4-4-4-12)
func Parse(s string) (UUID, error) {
	if len(s) != 36 {
		return UUID{}, ErrInvalidLength
	}

	// Check dash positions
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return UUID{}, ErrInvalidFormat
	}

	var out UUID
	// Parse directly without intermediate array allocation
	// Positions: 0-1, 2-3, 4-5, 6-7, 9-10, 11-12, 14-15, 16-17,
	//            19-20, 21-22, 24-25, 26-27, 28-29, 30-31, 32-33, 34-35
	for i := range 16 {
		var pos int
		if i < 4 {
			pos = i * 2
		} else if i < 6 {
			pos = i*2 + 1
		} else if i < 8 {
			pos = i*2 + 2
		} else if i < 10 {
			pos = i*2 + 3
		} else {
			pos = i*2 + 4
		}

		h := hexval(s[pos])
		l := hexval(s[pos+1])
		if h < 0 || l < 0 {
			return UUID{}, ErrInvalidHex
		}
		out[i] = byte((h << 4) | l)
	}
	return out, nil
}

// String returns the UUID in canonical format (8-4-4-4-12)
func (u *UUID) String() string {
	var buf [36]byte
	hexd := "0123456789abcdef"
	dpos := []int{4, 6, 8, 10}

	j := 0
	for i := range 16 {
		if i == dpos[0] || i == dpos[1] || i == dpos[2] || i == dpos[3] {
			buf[j] = '-'
			j++
		}
		buf[j] = hexd[(u[i]>>4)&0xF]
		j++
		buf[j] = hexd[u[i]&0xF]
		j++
	}
	return string(buf[:])
}

// Bytes returns the UUID as a byte slice
func (u *UUID) Bytes() []byte {
	return u[:]
}

// SetBytes sets the UUID from a byte slice
func (u *UUID) SetBytes(b []byte) error {
	if len(b) != 16 {
		return ErrInvalidByteSlice
	}
	copy(u[:], b)
	return nil
}

// IsZero returns true if the UUID is all zeros
func (u *UUID) IsZero() bool {
	return *u == UUID{}
}

// Equal returns true if two UUIDs are equal
func (u *UUID) Equal(other UUID) bool {
	return *u == other
}

// MarshalText implements encoding.TextMarshaler
func (u UUID) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler
func (u *UUID) UnmarshalText(text []byte) error {
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}
