package main

import (
	"fmt"

	"github.com/srinivengala/cryptmt/core"
	"github.com/srinivengala/cryptmt/ecrypt"
)

func main() {
	var i int
	var x core.Ctx
	var plaintext [128]uint8
	var plaintext2 [128]uint8
	var ciphertext [128]uint8

	for i = 0; i < 128; i++ {
		plaintext[i] = 0
	}

	ecrypt.KeySetup(&x, "1234567812345678", 128, 128)
	ecrypt.IVSetup(&x, "8765432187654321")
	ecrypt.EncryptBytes(&x, plaintext, ciphertext, 128)
	for i = 0; i < 16; i++ {
		fmt.Printf("%2x ", ciphertext[i])
	}
	fmt.Printf("\n")

	ecrypt.IVSetup(&x, "8765432187654321")
	ecrypt.DecryptBytes(&x, ciphertext, plaintext2, 128)
	for i = 0; i < 16; i++ {
		fmt.Printf("%2x ", plaintext2[i])
	}
	fmt.Printf("\n")
}
