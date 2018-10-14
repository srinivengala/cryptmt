// Package cryptmt is CryptMT v1.0 implementation
// By Hagita-Matsumoto-Nishimura-Saito
//
// ported to go by Srinivas Vengala - 7 October 2018
package cryptmt

// Overhead is the number of bytes of overhead when boxing a message.
const Overhead = 64

// SecretBox blah
type SecretBox struct {
}

// Seal appends an encrypted and authenticated copy of message to out, which
// must not overlap message. The key and nonce pair must be unique for each
// distinct message and the output will be Overhead bytes longer than message.
func Seal(out, message []byte, nonce *[24]byte, key *[32]byte) []byte {
	return nil
}

// Open authenticates and decrypts a box produced by Seal and appends the
// message to out, which must not overlap box. The output will be Overhead
// bytes smaller than box.
func Open(out, box []byte, nonce *[24]byte, key *[32]byte) ([]byte, bool) {
	return nil, false
}
