package main

import (
	"fmt"

	"github.com/srinivengala/cryptmt/core"
	"github.com/srinivengala/cryptmt/ecrypt"
)

func main() {
	var i int
	var x core.Ctx
	var plaintext [128]byte
	var plaintext2 [128]byte
	var ciphertext [128]byte

	for i = 0; i < 128; i++ {
		plaintext[i] = 5
	}

	ecrypt.KeySetup(&x, []byte("1234567812345678"), 128, 128)
	ecrypt.IVSetup(&x, []byte("8765432187654321"))
	ecrypt.EncryptBytes(&x, plaintext[:], ciphertext[:], 128)
	for i = 0; i < 16; i++ {
		fmt.Printf("%2x ", ciphertext[i])
	}
	fmt.Printf("\n")

	ecrypt.IVSetup(&x, []byte("8765432187654321"))
	ecrypt.DecryptBytes(&x, ciphertext[:], plaintext2[:], 128)
	for i = 0; i < 16; i++ {
		fmt.Printf("%2x ", plaintext2[i])
	}
	fmt.Printf("\n")
}
