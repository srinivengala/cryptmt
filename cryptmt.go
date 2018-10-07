// Package cryptmt is CryptMT v1.0 implementation
// By Hagita-Matsumoto-Nishimura-Saito
//
// ported to go by Srinivas Vengala - 7 October 2018
package cryptmt

import (
	"crypto/cipher"
	"errors"

	"github.com/srinivengala/cryptmt/core"
	"github.com/srinivengala/cryptmt/ecrypt"
)

// Implement cipher.AEAD, cipher.Block, cipher.Stream
//

// Aead Implements cipher.AEAD
type Aead struct {
	ctx *core.Ctx
}

// NewAead returns cryptmt aead implementation
func NewAead(key []byte, IV []byte) (cipher.AEAD, error) {
	c := new(Aead)
	if err := ecrypt.KeySetup(c.ctx, key[:]); err != nil {
		return nil, err
	}
	if err := ecrypt.IVSetup(c.ctx, IV[:]); err != nil {
		return nil, err
	}
	return c, nil
}

// NonceSize returns the size of the nonce that must be passed to Seal
// and Open.
func (c *Aead) NonceSize() int {
	return 0
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (c *Aead) Overhead() int {
	return 0
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
//
// The plaintext and dst must overlap exactly or not at all. To reuse
// plaintext's storage for the encrypted output, use plaintext[:0] as dst.
func (c *Aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return nil
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// The ciphertext and dst must overlap exactly or not at all. To reuse
// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (c *Aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
