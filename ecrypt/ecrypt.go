package ecrypt

import (
	"errors"
	"strconv"

	"github.com/srinivengala/cryptmt/random"
)

// MaxKeySizeBits is max key size supported by this cipher
const MaxKeySizeBits = 2048

// KeySizeBits to iterate through key sizes
func KeySizeBits(i int) int {
	return 128 + i*32
}

// MaxIVSizeBits is max IV size supported
const MaxIVSizeBits = 2048

// IVSizeBits iterator
func IVSizeBits(i int) int {
	return 128 + i*32
}

// Ecrypt Implementation
type Ecrypt struct {
	ctx         *random.Ctx
	KeySizeBits uint32 // size in bits
	IVSizeBits  uint32 // size in bits
	Key         [MaxKeySizeBits / 8]byte
	IV          [MaxIVSizeBits / 8]byte
}

/* This is a stream cipher. The algorithm is as follows. */
/* Generate 32 bit nonsecure random numbers by MT. */
/* Multiply three consequtive words, and use only */
/* the most significant 8 bits. */

// New to Init cipher
func New() *Ecrypt {
	return &Ecrypt{}
}

// KeySetup blah
func (e *Ecrypt) KeySetup(key []byte) error {

	var i uint32
	keySizeBits := uint32(len(key) * 8)

	if keySizeBits < uint32(KeySizeBits(0)) ||
		keySizeBits > uint32(MaxKeySizeBits) {
		return errors.New("Key size should be in range [" +
			strconv.Itoa(KeySizeBits(0)) + ", " +
			strconv.Itoa(MaxKeySizeBits) + "]")
	}

	e.KeySizeBits = keySizeBits

	for i = 0; i < keySizeBits/8; i++ {
		e.Key[i] = key[i]
	}

	return nil
}

// IVSetup blah
func (e *Ecrypt) IVSetup(iv []byte) error {
	ivSizeBits := uint32(len(iv) * 8)
	if ivSizeBits < uint32(IVSizeBits(0)) || ivSizeBits > uint32(MaxIVSizeBits) {
		return errors.New("IV size should be in range [" +
			strconv.Itoa(IVSizeBits(0)) + ", " +
			strconv.Itoa(MaxIVSizeBits) + "]")
	}
	e.IVSizeBits = ivSizeBits

	var j int32
	var i, t, x, k, s uint32
	var initArray [(MaxKeySizeBits + MaxIVSizeBits) / 32]uint32

	for _, v := range iv {
		e.IV[i] = v
	}

	j = 0
	t = e.KeySizeBits / 32
	for i = 0; i < t; i++ {
		x = uint32(e.Key[j])
		j++
		x |= uint32(e.Key[j]) << 8
		j++
		x |= uint32(e.Key[j]) << 16
		j++
		x |= uint32(e.Key[j]) << 24
		j++
		initArray[i] = x
	}
	if e.KeySizeBits%32 != 0 {
		x = 0
		k = (e.KeySizeBits % 32) / 8
		for i = 0; i < k; i++ {
			x |= uint32(e.Key[j]) << (8 * k)
			j++
		}
		initArray[t] = x
		t++
	}

	j = 0
	s = e.IVSizeBits / 32
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
	if e.IVSizeBits%32 != 0 {
		x = 0
		k = (e.IVSizeBits % 32) / 8
		for i = 0; i < k; i++ {
			x |= uint32(e.IV[j]) << (8 * k)
			j++
		}
		initArray[t+s] = x
		s++
	}
	e.ctx = random.NewArraySeeded(initArray[:]) // Initialize MT

	e.ctx.Accum = 1
	for i = 0; i < 64; i++ { // warm up : idling 64 times
		e.ctx.Accum *= (e.ctx.GenrandInt32() | 0x1)
	}
	return nil
}

// EncryptBytes blah
func (e *Ecrypt) EncryptBytes(
	plaintext []byte,
	ciphertext []byte,
	msglen uint32) { // Message length in bytes.

	var i uint32
	for i = 0; i < msglen; i++ {
		e.ctx.Accum *= (e.ctx.GenrandInt32() | 0x1)
		ciphertext[i] = plaintext[i] ^ uint8(e.ctx.Accum>>24)
	}
}

// DecryptBytes blah
func (e *Ecrypt) DecryptBytes(
	ciphertext []byte,
	plaintext []byte,
	msglen uint32) { /* Message length in bytes. */

	var i uint32
	for i = 0; i < msglen; i++ {
		e.ctx.Accum *= (e.ctx.GenrandInt32() | 0x1)
		plaintext[i] = ciphertext[i] ^ uint8(e.ctx.Accum>>24)
	}
}

// KeystreamBytes blah
func (e *Ecrypt) KeystreamBytes(
	keystream []byte,
	msglen uint32) {

	var i uint32
	for i = 0; i < msglen; i++ {
		e.ctx.Accum *= (e.ctx.GenrandInt32() | 0x1)
		keystream[i] = uint8(e.ctx.Accum >> 24)
	}
}
