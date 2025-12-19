// Copyright 2025 CastleBytes https://castlebytes.com
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package uuid47

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func leU64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}

func TestRdWr48(t *testing.T) {
	buf := make([]byte, 6)
	v := uint64(0x0123456789AB) & 0x0000FFFFFFFFFFFF
	wr48be(buf, v)
	r := rd48be(buf)
	if r != v {
		t.Errorf("rd48be/wr48be roundtrip failed: got 0x%X, want 0x%X", r, v)
	}
}

func TestUUIDParseFormatRoundtrip(t *testing.T) {
	// Correct 8-4-4-4-12 layout; version nibble '7' at start of 3rd group; RFC variant '8' in 4th.
	s := "00000000-0000-7000-8000-000000000000"
	u, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if u.Version() != 7 {
		t.Errorf("Version: got %d, want 7", u.Version())
	}

	out := u.String()
	u2, err := Parse(out)
	if err != nil {
		t.Fatalf("Parse roundtrip failed: %v", err)
	}
	if u != u2 {
		t.Errorf("Roundtrip mismatch: got %v, want %v", u2, u)
	}

	// Test bad input
	bad := "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
	_, err = Parse(bad)
	if err == nil {
		t.Error("Expected error parsing invalid UUID, got nil")
	}
}

func TestVersionVariant(t *testing.T) {
	var u UUID
	u.setVersion(7)
	if u.Version() != 7 {
		t.Errorf("Version: got %d, want 7", u.Version())
	}
	u.setVariantRFC4122()
	if (u[8] & 0xC0) != 0x80 {
		t.Errorf("Variant bits: got 0x%X, want 0x80", u[8]&0xC0)
	}
}

func TestSipHashSwitchAndVectorsSubset(t *testing.T) {
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)

	// Test vectors from SipHash reference
	vbytes := [][]byte{
		{0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72}, // len 0
		{0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74}, // len 1
		{0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d}, // len 2
		{0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85}, // len 3
		{0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf}, // len 4
		{0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18}, // len 5
		{0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb}, // len 6
		{0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab}, // len 7
		{0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93}, // len 8
		{0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e}, // len 9
		{0xf3, 0xb9, 0xdd, 0x94, 0xc5, 0xbb, 0x5d, 0x7a}, // len 10
		{0xa7, 0xad, 0x6b, 0x22, 0x46, 0x2f, 0xb3, 0xf4}, // len 11
		{0xfb, 0xe5, 0x0e, 0x86, 0xbc, 0x8f, 0x1e, 0x75}, // len 12
	}

	msg := make([]byte, 64)
	for i := range 64 {
		msg[i] = byte(i)
	}

	for length := range 13 {
		got := siphash24(msg[:length], k0, k1)
		exp := leU64(vbytes[length])
		if got != exp {
			t.Errorf("SipHash24 len=%d: got 0x%016X, want 0x%016X", length, got, exp)
		}
	}

	// Exercise extra tail paths
	_ = siphash24(msg[:15], k0, k1)
}

func craftV7(tsMs48 uint64, randA12 uint16, randB62 uint64) UUID {
	var u UUID
	wr48be(u[0:6], tsMs48&0x0000FFFFFFFFFFFF)
	u.setVersion(7)
	u[6] = byte((u[6] & 0xF0) | byte((randA12>>8)&0x0F))
	u[7] = byte(randA12 & 0xFF)
	u.setVariantRFC4122()
	u[8] = byte((u[8] & 0xC0) | byte((randB62>>56)&0x3F))
	for i := range 7 {
		u[9+i] = byte((randB62 >> (8 * (6 - i))) & 0xFF)
	}
	return u
}

func TestBuildSipInputStability(t *testing.T) {
	u7 := craftV7(0x123456789ABC, 0x0ABC, 0x0123456789ABCDEF&((1<<62)-1))
	key := Key{K0: 0x0123456789abcdef, K1: 0xfedcba9876543210}
	facade := Encode(u7, key)

	var m1, m2 [10]byte
	buildSipInputFromV7(&u7, &m1)
	buildSipInputFromV7(&facade, &m2)
	if !bytes.Equal(m1[:], m2[:]) {
		t.Errorf("Sip input mismatch:\nv7:     %x\nfacade: %x", m1, m2)
	}
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	key := Key{K0: 0x0123456789abcdef, K1: 0xfedcba9876543210}

	for i := range 16 {
		ts := uint64((0x100000 * i) + 123)
		ra := uint16((0x0AAA ^ (i * 7)) & 0x0FFF)
		rb := (0x0123456789ABCDEF ^ (0x1111111111111111 * uint64(i))) & ((1 << 62) - 1)
		u7 := craftV7(ts, ra, rb)

		facade := Encode(u7, key)
		if facade.Version() != 4 {
			t.Errorf("Facade version: got %d, want 4", facade.Version())
		}
		if (facade[8] & 0xC0) != 0x80 {
			t.Errorf("Facade variant bits: got 0x%X, want 0x80", facade[8]&0xC0)
		}

		back := Decode(facade, key)
		if u7 != back {
			t.Errorf("Roundtrip %d failed:\noriginal: %v\nback:     %v", i, u7, back)
		}

		// Test with wrong key
		wrong := Key{K0: key.K0 ^ 0xdeadbeef, K1: key.K1 ^ 0x1337}
		bad := Decode(facade, wrong)
		if u7 == bad {
			t.Errorf("Wrong key should produce different result")
		}
	}
}

func TestBytes(t *testing.T) {
	u := UUID{
		0x01, 0x8f, 0x2d, 0x9f, 0x9a, 0x2a, 0x7d, 0xef,
		0x8c, 0x3f, 0x7b, 0x1a, 0x2c, 0x4d, 0x5e, 0x6f,
	}
	b := u.Bytes()
	if len(b) != 16 {
		t.Errorf("Bytes() length: got %d, want 16", len(b))
	}
	if !bytes.Equal(b, u[:]) {
		t.Errorf("Bytes() mismatch")
	}
}

func TestSetBytes(t *testing.T) {
	b := []byte{
		0x01, 0x8f, 0x2d, 0x9f, 0x9a, 0x2a, 0x7d, 0xef,
		0x8c, 0x3f, 0x7b, 0x1a, 0x2c, 0x4d, 0x5e, 0x6f,
	}
	var u UUID
	err := u.SetBytes(b)
	if err != nil {
		t.Fatalf("SetBytes() error: %v", err)
	}
	if !bytes.Equal(u[:], b) {
		t.Errorf("SetBytes() mismatch")
	}

	// Test invalid length
	err = u.SetBytes([]byte{1, 2, 3})
	if err != ErrInvalidByteSlice {
		t.Errorf("SetBytes() with invalid length: got %v, want %v", err, ErrInvalidByteSlice)
	}
}

func TestIsZero(t *testing.T) {
	var u UUID
	if !u.IsZero() {
		t.Error("IsZero() should return true for zero UUID")
	}

	u[0] = 1
	if u.IsZero() {
		t.Error("IsZero() should return false for non-zero UUID")
	}
}

func TestEqual(t *testing.T) {
	u1 := UUID{
		0x01, 0x8f, 0x2d, 0x9f, 0x9a, 0x2a, 0x7d, 0xef,
		0x8c, 0x3f, 0x7b, 0x1a, 0x2c, 0x4d, 0x5e, 0x6f,
	}
	u2 := UUID{
		0x01, 0x8f, 0x2d, 0x9f, 0x9a, 0x2a, 0x7d, 0xef,
		0x8c, 0x3f, 0x7b, 0x1a, 0x2c, 0x4d, 0x5e, 0x6f,
	}
	u3 := UUID{
		0x02, 0x8f, 0x2d, 0x9f, 0x9a, 0x2a, 0x7d, 0xef,
		0x8c, 0x3f, 0x7b, 0x1a, 0x2c, 0x4d, 0x5e, 0x6f,
	}

	if !u1.Equal(u2) {
		t.Error("Equal() should return true for identical UUIDs")
	}
	if u1.Equal(u3) {
		t.Error("Equal() should return false for different UUIDs")
	}
}

func TestSetVersion(t *testing.T) {
	var u UUID
	u.SetVersion(7)
	if u.Version() != 7 {
		t.Errorf("SetVersion(7): got version %d, want 7", u.Version())
	}

	u.SetVersion(4)
	if u.Version() != 4 {
		t.Errorf("SetVersion(4): got version %d, want 4", u.Version())
	}
}

func TestSetVariantRFC4122(t *testing.T) {
	var u UUID
	u.SetVariantRFC4122()
	if (u[8] & 0xC0) != 0x80 {
		t.Errorf("SetVariantRFC4122(): got variant bits 0x%X, want 0x80", u[8]&0xC0)
	}
}

func TestErrorConstants(t *testing.T) {
	// Test that error constants are defined
	if ErrInvalidLength == nil {
		t.Error("ErrInvalidLength should not be nil")
	}
	if ErrInvalidFormat == nil {
		t.Error("ErrInvalidFormat should not be nil")
	}
	if ErrInvalidHex == nil {
		t.Error("ErrInvalidHex should not be nil")
	}
	if ErrInvalidByteSlice == nil {
		t.Error("ErrInvalidByteSlice should not be nil")
	}

	// Test Parse returns proper errors
	_, err := Parse("too-short")
	if err != ErrInvalidLength {
		t.Errorf("Parse short string: got %v, want %v", err, ErrInvalidLength)
	}

	_, err = Parse("01234567-1234-1234-1234-1234567890zz")
	if err != ErrInvalidHex {
		t.Errorf("Parse invalid hex: got %v, want %v", err, ErrInvalidHex)
	}

	_, err = Parse("01234567_1234_1234_1234_123456789012")
	if err != ErrInvalidFormat {
		t.Errorf("Parse invalid format: got %v, want %v", err, ErrInvalidFormat)
	}
}
