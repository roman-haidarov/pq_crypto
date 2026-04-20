package main

import (
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"os"
)

func mustHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return b
}

func mustHexEncode(b []byte) {
	fmt.Println(hex.EncodeToString(b))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go_mlkem_interop <command> [args...]")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "keygen-from-seed":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		seed := mustHexDecode(os.Args[2])
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		mustHexEncode(dk.EncapsulationKey().Bytes())
	case "pub-roundtrip":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		pub := mustHexDecode(os.Args[2])
		ek, err := mlkem.NewEncapsulationKey768(pub)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		mustHexEncode(ek.Bytes())
	case "encap":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		pub := mustHexDecode(os.Args[2])
		ek, err := mlkem.NewEncapsulationKey768(pub)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		shared, ciphertext := ek.Encapsulate()
		mustHexEncode(ciphertext)
		mustHexEncode(shared)
	case "decap":
		if len(os.Args) != 4 {
			os.Exit(2)
		}
		seed := mustHexDecode(os.Args[2])
		ciphertext := mustHexDecode(os.Args[3])
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		shared, err := dk.Decapsulate(ciphertext)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		mustHexEncode(shared)
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}
