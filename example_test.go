// Copyright 2025 CastleBytes https://castlebytes.com
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package uuid47

import (
	"fmt"
)

// Example demonstrates the typical usage of the uuidv47 package:
// parsing a UUIDv7, encoding it as a UUIDv4 façade for external APIs,
// and decoding it back to the original UUIDv7.
func Example() {
	// Define your secret key (128 bits)
	// In production, load this from a secure key management system
	key := Key{K0: 0x0123456789abcdef, K1: 0xfedcba9876543210}

	// Parse a UUIDv7 (e.g., retrieved from your database)
	s := "018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f"
	idV7, err := Parse(s)
	if err != nil {
		panic(err)
	}

	// Check the version
	fmt.Printf("Version: %d\n", idV7.Version())

	// Encode to UUIDv4 façade (for external API responses)
	facade := Encode(idV7, key)

	// Decode back to UUIDv7 (when receiving from API or validating)
	back := Decode(facade, key)

	// Display the transformation
	fmt.Printf("v7 in : %s\n", idV7.String())
	fmt.Printf("v4 out: %s\n", facade.String())
	fmt.Printf("back  : %s\n", back.String())

	// Verify round-trip
	if idV7.Equal(back) {
		fmt.Println("Round-trip: success")
	}

	// Output:
	// Version: 7
	// v7 in : 018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f
	// v4 out: 2463c780-7fca-4def-8c3f-7b1a2c4d5e6f
	// back  : 018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f
	// Round-trip: success
}
