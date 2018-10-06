package ecrypt

import (
	"github.com/srinivengala/cryptmt/core"
)

const n = 624
const m = 397

/* This is a stream cipher. The algorithm is as follows. */
/* Generate 32 bit nonsecure random numbers by MT. */
/* Multiply three consequtive words, and use only */
/* the most significant 8 bits. */

// Init cipher
func Init() {
	/* do nothing */
}

// KeySetup blah
func KeySetup(
	ctx *core.Ctx,
	key []uint8,
	keysize uint32, /* Key size in bits. */
	ivsize uint32) { /* IV size in bits. */
	var i uint32

	ctx.Keysize = keysize
	ctx.IVSize = ivsize

	for i = 0; i < keysize/8; i++ {
		ctx.Key[i] = key[i]
	}

	ctx.Mti = n + 1 /* mti==N+1 means mt[N] is not initialized */
}

// IVSetup blah
func IVSetup(
	ctx *core.Ctx,
	iv []uint8) {
	var j int32
	var i, t, x, k, s uint32
	var initArray [(core.MaxKeySize + core.MaxIVSize) / 32]uint32

	for i = 0; i < ctx.IVSize/8; i++ {
		ctx.IV[i] = iv[i]
	}

	j = 0
	t = ctx.Keysize / 32
	for i = 0; i < t; i++ {
		x = uint32(ctx.Key[j])
		j++
		x |= uint32(ctx.Key[j]) << 8
		j++
		x |= uint32(ctx.Key[j]) << 16
		j++
		x |= uint32(ctx.Key[j]) << 24
		j++
		initArray[i] = x
	}
	if ctx.Keysize%32 != 0 {
		x = 0
		k = (ctx.Keysize % 32) / 8
		for i = 0; i < k; i++ {
			x |= uint32(ctx.Key[j]) << (8 * k)
			j++
		}
		initArray[t] = x
		t++
	}

	j = 0
	s = ctx.IVSize / 32
	for i = 0; i < s; i++ {
		x = uint32(ctx.IV[j])
		j++
		x |= uint32(ctx.IV[j]) << 8
		j++
		x |= uint32(ctx.IV[j]) << 16
		j++
		x |= uint32(ctx.IV[j]) << 24
		j++
		initArray[t+i] = x
	}
	if ctx.IVSize%32 != 0 {
		x = 0
		k = (ctx.IVSize % 32) / 8
		for i = 0; i < k; i++ {
			x |= uint32(ctx.IV[j]) << (8 * k)
			j++
		}
		initArray[t+(s)] = x
		s++
	}
	core.InitByArray(ctx, initArray[:], uint(t+s))

	ctx.Accum = 1
	for i = 0; i < 64; i++ { /* idling 64 times */
		ctx.Accum *= (core.GenrandInt32(ctx) | 0x1)
	}
}

// EncryptBytes blah
func EncryptBytes(
	ctx *core.Ctx,
	plaintext []uint8,
	ciphertext []uint8,
	msglen uint32) { /* Message length in bytes. */
	var i uint32
	for i = 0; i < msglen; i++ {
		ctx.Accum *= (core.GenrandInt32(ctx) | 0x1)
		ciphertext[i] = plaintext[i] ^ (ctx.Accum >> 24)
	}
}

// DecryptBytes blah
func DecryptBytes(
	ctx *core.Ctx,
	ciphertext []uint8,
	plaintext []uint8,
	msglen uint32) { /* Message length in bytes. */
	var i int32
	for i = 0; i < msglen; i++ {
		ctx.Accum *= (core.GenrandInt32(ctx) | 0x1)
		plaintext[i] = ciphertext[i] ^ (ctx.Accum >> 24)
	}
}

// KeystreamBytes blah
func KeystreamBytes(
	ctx *core.Ctx,
	keystream []uint8,
	msglen uint32) {
	var i int32
	for i = 0; i < msglen; i++ {
		ctx.Accum *= (core.GenrandInt32(ctx) | 0x1)
		keystream[i] = (ctx.Accum >> 24)
	}
}
