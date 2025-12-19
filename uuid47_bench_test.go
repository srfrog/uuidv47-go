// Copyright 2025 CastleBytes https://castlebytes.com
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package uuid47

import (
	"testing"
)

// xorshift64star is a simple PRNG for benchmark data generation
type xorshift64star uint64

func (x *xorshift64star) next() uint64 {
	v := uint64(*x)
	v ^= v >> 12
	v ^= v << 25
	v ^= v >> 27
	*x = xorshift64star(v)
	return v * 2685821657736338717
}

// BenchmarkEncodeDecodePair benchmarks the full encode+decode roundtrip
func BenchmarkEncodeDecodePair(b *testing.B) {
	key := Key{K0: 0x0123456789abcdef, K1: 0xfedcba9876543210}
	rng := xorshift64star(0x9e3779b97f4a7c15)

	// Pre-generate test data to avoid measuring RNG in the benchmark
	type testData struct {
		ts uint64
		ra uint16
		rb uint64
	}
	data := make([]testData, 1024)
	for i := range data {
		data[i] = testData{
			ts: rng.next() & 0x0000FFFFFFFFFFFF,
			ra: uint16(rng.next() & 0x0FFF),
			rb: rng.next() & ((1 << 62) - 1),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := data[i&1023]
		u7 := craftV7(d.ts, d.ra, d.rb)
		facade := Encode(u7, key)
		back := Decode(facade, key)

		// Prevent dead code elimination
		if back[0] == 0xFF && back[15] == 0xFF {
			b.Fatal("unexpected")
		}
	}
}

// BenchmarkEncode benchmarks only the encode operation
func BenchmarkEncode(b *testing.B) {
	key := Key{K0: 0x0123456789abcdef, K1: 0xfedcba9876543210}
	rng := xorshift64star(0x9e3779b97f4a7c15)

	// Pre-generate v7 UUIDs
	uuids := make([]UUID, 1024)
	for i := range uuids {
		ts := rng.next() & 0x0000FFFFFFFFFFFF
		ra := uint16(rng.next() & 0x0FFF)
		rb := rng.next() & ((1 << 62) - 1)
		uuids[i] = craftV7(ts, ra, rb)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u7 := uuids[i&1023]
		facade := Encode(u7, key)

		// Prevent dead code elimination
		if facade[0] == 0xFF && facade[15] == 0xFF {
			b.Fatal("unexpected")
		}
	}
}

// BenchmarkDecode benchmarks only the decode operation
func BenchmarkDecode(b *testing.B) {
	key := Key{K0: 0x0123456789abcdef, K1: 0xfedcba9876543210}
	rng := xorshift64star(0x9e3779b97f4a7c15)

	// Pre-generate v4 facades
	facades := make([]UUID, 1024)
	for i := range facades {
		ts := rng.next() & 0x0000FFFFFFFFFFFF
		ra := uint16(rng.next() & 0x0FFF)
		rb := rng.next() & ((1 << 62) - 1)
		u7 := craftV7(ts, ra, rb)
		facades[i] = Encode(u7, key)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		facade := facades[i&1023]
		back := Decode(facade, key)

		// Prevent dead code elimination
		if back[0] == 0xFF && back[15] == 0xFF {
			b.Fatal("unexpected")
		}
	}
}

// BenchmarkSipHash24_10B benchmarks just the SipHash-2-4 function with 10-byte input
func BenchmarkSipHash24_10B(b *testing.B) {
	key := Key{K0: 0x0123456789abcdef, K1: 0xfedcba9876543210}
	rng := xorshift64star(0x7f4a7c159e3779b9)

	// Pre-generate 10-byte messages
	messages := make([][10]byte, 1024)
	for i := range messages {
		ts := rng.next() & 0x0000FFFFFFFFFFFF
		ra := uint16(rng.next() & 0x0FFF)
		rb := rng.next() & ((1 << 62) - 1)
		u7 := craftV7(ts, ra, rb)
		buildSipInputFromV7(&u7, &messages[i])
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := messages[i&1023]
		out := siphash24(msg[:], key.K0, key.K1)

		// Prevent dead code elimination
		if out == 0 {
			b.Fatal("unexpected")
		}
	}
}

// BenchmarkUUIDParse benchmarks UUID string parsing
func BenchmarkUUIDParse(b *testing.B) {
	s := "018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u, err := Parse(s)
		if err != nil {
			b.Fatal(err)
		}
		// Prevent dead code elimination
		if u[0] == 0xFF {
			b.Fatal("unexpected")
		}
	}
}

// BenchmarkUUIDString benchmarks UUID string formatting
func BenchmarkUUIDString(b *testing.B) {
	u := UUID{
		0x01, 0x8f, 0x2d, 0x9f, 0x9a, 0x2a, 0x7d, 0xef,
		0x8c, 0x3f, 0x7b, 0x1a, 0x2c, 0x4d, 0x5e, 0x6f,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := u.String()
		// Prevent dead code elimination
		if s == "" {
			b.Fatal("unexpected")
		}
	}
}

// BenchmarkUUIDParseFormat benchmarks the roundtrip of parse and format
func BenchmarkUUIDParseFormat(b *testing.B) {
	s := "018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u, err := Parse(s)
		if err != nil {
			b.Fatal(err)
		}
		out := u.String()
		// Prevent dead code elimination
		if out == "" {
			b.Fatal("unexpected")
		}
	}
}
