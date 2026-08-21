// go:build ignore
//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"github.com/custodexa/backend/pkg/crypto"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run generate_hash.go <password>")
		os.Exit(1)
	}

	password := os.Args[1]
	hash, err := crypto.DefaultPasswordHasher().Hash([]byte(password))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(hash))
}
