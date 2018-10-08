package main

import (
	"crypto/rand"
	"fmt"

	"github.com/srinivengala/cryptmt/ecrypt"
)

func main() {

	fmt.Println("Key sizes in bytes:", ecrypt.GetKeySizesString(", "))

	fmt.Println("****")
	simpleTestKeysize(60, 255, 15)
	fmt.Println("****")
	simpleTestKeysize(60, 256, 17)
	fmt.Println("****")
	simpleTestKeysize(60, 16, 16)
	fmt.Println("****")
	simpleTestKeysize(60, 256, 256)
	fmt.Println("****")
	simpleTestKeysize(60, 16, 256)
	fmt.Println("****")
	simpleTestKeysize(60, 256, 16)
}

func simpleTestKeysize(textSize int, keySize int, ivSize int) {
	var i int
	ecrypt := ecrypt.New()
	plaintext := make([]byte, textSize)
	plaintext2 := make([]byte, textSize)
	ciphertext := make([]byte, textSize)

	for i = 0; i < textSize; i++ {
		plaintext[i] = 0
	}

	//key := bytes.Repeat([]byte("12345678"), keySize/16)
	//iv := bytes.Repeat([]byte("87654321"), ivSize/16)
	key := make([]byte, keySize)
	iv := make([]byte, ivSize)
	rand.Read(key)
	rand.Read(iv)

	if err := ecrypt.KeySetup(key); err != nil {
		fmt.Println("Error: KeySetup ", err.Error())
		return
	}
	if err := ecrypt.IVSetup(iv); err != nil {
		fmt.Println("Error: IVSetup ", err.Error())
		return
	}
	ecrypt.EncryptBytes(plaintext[:], ciphertext[:], uint32(textSize))

	//iv = bytes.Repeat([]byte("87654321"), ivSize/16)
	ecrypt.IVSetup(iv)
	ecrypt.DecryptBytes(ciphertext[:], plaintext2[:], uint32(textSize))

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
	var plaintext [128]byte
	var plaintext2 [128]byte
	var ciphertext [128]byte

	for i = 0; i < 128; i++ {
		plaintext[i] = 0
	}

	ecrypt := ecrypt.New()
	ecrypt.KeySetup([]byte("1234567812345678"))
	ecrypt.IVSetup([]byte("8765432187654321"))
	ecrypt.EncryptBytes(plaintext[:], ciphertext[:], 128)
	for i = 0; i < 16; i++ {
		fmt.Printf("%2x ", ciphertext[i])
	}
	fmt.Printf("\n")

	ecrypt.IVSetup([]byte("8765432187654321"))
	ecrypt.DecryptBytes(ciphertext[:], plaintext2[:], 128)
	for i = 0; i < 16; i++ {
		fmt.Printf("%2x ", plaintext2[i])
	}
	fmt.Printf("\n")
}
