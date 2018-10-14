package ecrypt

import (
	"errors"
	"strconv"
	"strings"

	"github.com/srinivengala/cryptmt/random"
)

// MaxKeySize is max key size bytes supported by this cipher
const MaxKeySize = 2048 / 8

// KeySizeItr to iterate through key sizes
func KeySizeItr(i int) int {
	return (128 + i*32) / 8
}

// MaxIVSize is max IV size bytes supported by this cipher
const MaxIVSize = 2048 / 8

// IVSizeItr to iterate through IV sizes
func IVSizeItr(i int) int {
	return (128 + i*32) / 8
}

// GetKeySizes returns all supported key sizes as string
func GetKeySizes() []int {
	sizes := make([]int, 0, 62)
	sz := KeySizeItr(0)
	for i := 1; sz <= MaxKeySize; i++ {
		sizes = append(sizes, sz)
		sz = KeySizeItr(i)
	}
	return sizes
}

// GetKeySizesString makes a string of all supported key sizes
func GetKeySizesString(join string) string {
	ints := GetKeySizes()
	strs := make([]string, 0, len(ints))

	for _, v := range ints {
		strs = append(strs, strconv.Itoa(v))
	}
	return strings.Join(strs, join)
}

// GetKeySizeRange gets minimum and maximum supported key sizes
func GetKeySizeRange() (min, max int) {
	return KeySizeItr(0), MaxKeySize
}

// IsValidKeySize checks if the size in bytes is a valid key size
func IsValidKeySize(size int) bool {
	for _, v := range GetKeySizes() {
		if size == v {
			return true
		}
	}
	return false
}

// IsValidIVSize checks if the size in bytes is a valid IV size
func IsValidIVSize(size int) bool {
	return IsValidKeySize(size)
}

// Ecrypt Implementation
type Ecrypt struct {
	ctx     *random.Ctx
	keySize uint32 // size in bytes
	ivSize  uint32 // size in bytes
	key     []byte
	IV      []byte
	//Accum   uint32 // Accumulator
}

/* This is a stream cipher. The algorithm is as follows. */
/* Generate 32 bit nonsecure random numbers by MT. */
/* Multiply three consequtive words, and use only */
/* the most significant 8 bits. */

// New to Init cipher
func New() *Ecrypt {
	return &Ecrypt{}
}

// Recommended : (key length + iv length) == random.N * 4 == 624 * 4 == 2496 bytes

// KeySetup is just to capture first half of bytes needed for making MT initialization vector
func (e *Ecrypt) KeySetup(key []byte) error {
	keySize := len(key)

	if !IsValidKeySize(keySize) {
		return errors.New("Key size in bytes should be in range [" +
			strconv.Itoa(KeySizeItr(0)) + ", " +
			strconv.Itoa(MaxKeySize) + "]: " +
			GetKeySizesString(", "))
	}

	e.keySize = uint32(keySize)

	e.key = make([]byte, keySize)
	copy(e.key, key)

	return nil
}

// IVSetup is just to capture second half of bytes needed for making MT initialization vector
func (e *Ecrypt) IVSetup(iv []byte) error {
	ivSize := len(iv)
	if !IsValidIVSize(ivSize) {
		return errors.New("IV size in bytes should be in range [" +
			strconv.Itoa(IVSizeItr(0)) + ", " +
			strconv.Itoa(MaxIVSize) + "]: " +
			GetKeySizesString(", "))
	}
	e.ivSize = uint32(ivSize)

	e.IV = make([]byte, ivSize)
	copy(e.IV, iv) //copy works because e.IV memory is preallocated

	var j int32
	var i, t, x, k, s uint32
	var initArray [(MaxKeySize + MaxIVSize) / 4]uint32

	// Create randomish MT initialization vector from IV and Key bytes.
	j = 0
	t = e.keySize / 4 // t words from key
	for i = 0; i < t; i++ {
		x = uint32(e.key[j])
		j++
		x |= uint32(e.key[j]) << 8
		j++
		x |= uint32(e.key[j]) << 16
		j++
		x |= uint32(e.key[j]) << 24
		j++
		initArray[i] = x
	}
	if (e.keySize*8)%32 != 0 {
		x = 0
		k = ((e.keySize * 8) % 32) / 8
		for i = 0; i < k; i++ {
			x |= uint32(e.key[j]) << (8 * k)
			j++
		}
		initArray[t] = x
		t++
	}

	j = 0
	s = e.ivSize / 4 // s words from IV
	for i = 0; i < s; i++ {
		x = uint32(e.IV[j])
		j++
		x |= uint32(e.IV[j]) << 8
		j++
		x |= uint32(e.IV[j]) << 16
		j++
		x |= uint32(e.IV[j]) << 24
		j++
		initArray[t+i] = x
	}
	if (e.ivSize*8)%32 != 0 {
		x = 0
		k = ((e.ivSize * 8) % 32) / 8
		for i = 0; i < k; i++ {
			x |= uint32(e.IV[j]) << (8 * k)
			j++
		}
		initArray[t+s] = x
		s++
	}

	e.ctx = random.NewArraySeeded(initArray[:t+s]) // Initialize MT

	//e.Accum = 1
	e.ctx.Warmup()
	return nil
}

// EncryptBytes encrypts msglen bytes from plaintext to ciphertext
func (e *Ecrypt) EncryptBytes(
	plaintext []byte,
	ciphertext []byte,
	msglen uint32) { // Message length in bytes.

	var i uint32
	for i = 0; i < msglen; i++ {
		ciphertext[i] = plaintext[i] ^ e.next()
	}
}

// DecryptBytes decrypts msglen bytes from ciphertext to plaintext
func (e *Ecrypt) DecryptBytes(
	ciphertext []byte,
	plaintext []byte,
	msglen uint32) { // Message length in bytes.

	var i uint32
	for i = 0; i < msglen; i++ {
		plaintext[i] = ciphertext[i] ^ e.next()
	}
}

// KeystreamBytes returns msglen bytes of keystream pseudo random numbers
func (e *Ecrypt) KeystreamBytes(
	keystream []byte,
	msglen uint32) { // Message length in bytes

	var i uint32
	for i = 0; i < msglen; i++ {
		keystream[i] = e.next()
	}
}

// Next generates next keystream random byte
func (e *Ecrypt) next() byte {
	//e.Accum *= (e.ctx.NextWord() | 0x1)
	//return byte(e.Accum >> 24)
	return e.ctx.SecureNext()
}
