package ecrypt

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/srinivengala/cryptmt/random"

	"github.com/srinivengala/cryptmt/util"
)

func TestEncryptDecrypt(t *testing.T) {
	simpleTest()
}

func TestSeedingInt(t *testing.T) {
	fmt.Println("MT[       1 6c078966 dd5254a5 b9523b81  3df95b3 ca37daa4 1a9da2e9 9cbef6f4 923b1516 532304ed 3ce73d26 7afe7609 4dc6d934 66240ef6 34fd1681 626be9f4 ]")
	c := random.NewSeeded(1)
	c.DumpContext()
}

func TestSeeding(t *testing.T) {
	fmt.Println("MT[80000000 58a8fe4c df0469aa 5bafaa0e fb912ed6 1a77f7b5 63bfc56d 9d1a1d78 6a95ddaa ae832fc4 bab0fd73 15659e9d b2166f2e 5180cf0f fdbad23c 2ef218c6 ]")
	arr := make([]uint32, 32)
	c := random.NewArraySeeded(arr)
	c.DumpContext()
}

func TestVector2(t *testing.T) {
	//keyStr := "1234567812345678"
	//ivStr := "8765432187654321"
	stream := "77f199321d042a400d33bb936db719d2"

	pt := make([]byte, 128)
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}
	iv := []byte{8, 7, 6, 5, 4, 3, 2, 1, 8, 7, 6, 5, 4, 3, 2, 1}

	ct := make([]byte, len(pt))

	cipher := New()
	if err := cipher.KeySetup(key); err != nil {
		t.Error(err)
		return
	}
	if err := cipher.IVSetup(iv); err != nil {
		t.Error(err)
	}
	cipher.ctx.DumpContext()
	cipher.EncryptBytes(pt, ct, uint32(len(pt)))

	output := hex.EncodeToString(ct)

	t.Log(stream)
	t.Log(output[:len(stream)])

	if stream == output[:len(stream)] {
		t.Logf("success")
	} else {
		t.Fail()
	}
}

func TestVector(t *testing.T) {
	keyStr := "80000000000000000000000000000000"
	ivStr := "00000000000000000000000000000000"
	stream := "9F80406781E5996319BDF9DFD5629D30"

	pt := make([]byte, 512)
	key, _ := hex.DecodeString(keyStr)
	iv, _ := hex.DecodeString(ivStr)

	ct := make([]byte, len(pt))

	cipher := New()
	cipher.KeySetup(key)
	cipher.IVSetup(iv)
	cipher.EncryptBytes(pt, ct, uint32(len(pt)))

	output := hex.EncodeToString(ct)

	t.Log(stream)
	t.Log(output[:len(stream)])

	if stream == output[:len(stream)] {
		t.Logf("success")
	} else {
		t.Fail()
	}
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
