package main

// ecrypt sync header CryptMT-v1

const cmtMaxKeySize = 2048

func cmtkeySize(i int) int {
	return 128 + i*32
}

const cmtMaxIVSize = 2048

func cmtIVSize(i int) int {
	return 128 + i*32
}

// Period parameters
const n = 624
const m = 397
const matrixA = 0x9908B0DF   // constant vector a
const upperMask = 0x80000000 // most significant w-r bits
const lowerMask = 0x7FFFFFFF // least significant r bits

// initializes mt[N] with a seed
func init_genrand() {

}

func main() {

}
