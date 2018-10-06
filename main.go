package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/srinivengala/cryptmt/core"
	"github.com/srinivengala/cryptmt/ecrypt"
)

func main() {

	fmt.Print("Key sizes :")
	ks := 0
	for c := 0; ks < core.MaxKeySize; c++ {
		ks = core.KeySize(c)
		fmt.Print(" ", ks)
	}
	fmt.Println()
	fmt.Println()

	simpleTestKeysize(60, 2048, 128) //2048 bits or 256 bytes
}

func simpleTestKeysize(textSize int, keySize int, ivSize int) {
	var i int
	var x core.Ctx
	plaintext := make([]byte, textSize)
	plaintext2 := make([]byte, textSize)
	ciphertext := make([]byte, textSize)

	for i = 0; i < textSize; i++ {
		plaintext[i] = 0
	}

	key := bytes.Repeat([]byte("12345678"), keySize/16)
	iv := bytes.Repeat([]byte("87654321"), ivSize/16)

	err := ecrypt.KeySetup(&x, key, uint32(keySize), uint32(ivSize))
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	ecrypt.IVSetup(&x, iv)
	ecrypt.EncryptBytes(&x, plaintext[:], ciphertext[:], uint32(textSize))

	iv = bytes.Repeat([]byte("87654321"), ivSize/16)
	ecrypt.IVSetup(&x, iv)
	ecrypt.DecryptBytes(&x, ciphertext[:], plaintext2[:], uint32(textSize))

	display(plaintext2, ciphertext)
}

func display(plaintext []byte, ciphertext []byte) {
	i := 0
	j := 0

	if len(plaintext) < 32 {
		for i = 0; i < len(ciphertext); i++ {
			fmt.Printf(" %2x", ciphertext[i])
		}
		fmt.Println()
		for i = 0; i < len(plaintext); i++ {
			fmt.Printf(" %2x", plaintext[i])
		}
		fmt.Println()
		return
	}

	for j = 0; j < len(plaintext)/32; j++ {
		for i = 0; i < 16; i++ {
			fmt.Printf(" %2x", ciphertext[j*32+i])
		}
		fmt.Print(" :")
		for i = 0; i < 16; i++ {
			fmt.Printf(" %2x", ciphertext[j*32+16+i])
		}
		fmt.Println()
		for i = 0; i < 16; i++ {
			fmt.Printf(" %2x", plaintext[j*32+i])
		}
		fmt.Print(" :")
		for i = 0; i < 16; i++ {
			fmt.Printf(" %2x", plaintext[j*32+16+i])
		}
		fmt.Println()
	}
	remaining := len(plaintext) % 32
	if remaining != 0 {
		for i = 0; i < remaining; i++ {
			fmt.Printf(" %2x", ciphertext[len(ciphertext)-remaining+i])
		}
		fmt.Println()
		for i = 0; i < remaining; i++ {
			fmt.Printf(" %2x", plaintext[len(plaintext)-remaining+i])
		}
		fmt.Println()
	}
}

func simpleTest() {
	var i int
	var x core.Ctx
	var plaintext [128]byte
	var plaintext2 [128]byte
	var ciphertext [128]byte

	for i = 0; i < 128; i++ {
		plaintext[i] = 0
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
