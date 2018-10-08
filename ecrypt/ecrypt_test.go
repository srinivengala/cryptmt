package ecrypt

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/srinivengala/cryptmt/util"
)

func TestEncryptDecrypt(t *testing.T) {
	simpleTest()
}

func TestEcrypt(t *testing.T) {
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
	ecrypt := New()
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

	util.Display(plaintext2, ciphertext)
}

func simpleTest() {
	var i int
	var plaintext [128]byte
	var plaintext2 [128]byte
	var ciphertext [128]byte

	for i = 0; i < 128; i++ {
		plaintext[i] = 0
	}

	ecrypt := New()
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
