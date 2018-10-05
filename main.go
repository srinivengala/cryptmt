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

type ctx struct {
	Keysize int32 // size in bits
	IVSize  int32 // size in bits
	Key     [cmtMaxKeySize / 8]uint8
	IV      [cmtMaxIVSize / 8]uint8

	MT    [624]uint32
	Mti   int
	Accum uint32
}

// Period parameters
const n = 624
const m = 397
const matrixA uint32 = 0x9908B0DF   // constant vector a
const upperMask uint32 = 0x80000000 // most significant w-r bits
const lowerMask uint32 = 0x7FFFFFFF // least significant r bits

// initializes mt[N] with a seed
func initGenrand(c *ctx, s uint32) {
	c.MT[0] = s & uint32(0xFFFFFFFF)
	for c.Mti = 1; c.Mti < n; c.Mti++ {
		c.MT[c.Mti] = uint32(uint32(1812433253)*(c.MT[c.Mti-1]^(c.MT[c.Mti-1]>>30)) + uint32(c.Mti))
		/* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
		/* In the previous versions, MSBs of the seed affect   */
		/* only MSBs of the array mt[].                        */
		/* 2002/01/09 modified by Makoto Matsumoto             */
	}
}

/* initialize by an array with array-length */
/* init_key is the array for initializing keys */
/* key_length is its length */
/* slight change for C++, 2004/2/26 */
func initByArray(c *ctx, initKey []uint32, keyLength int) {
	var i, j, k int
	initGenrand(c, uint32(19650218))
	i = 1
	j = 0

	k = keyLength
	if keyLength < n {
		k = n
	}

	for ; k > 0; k-- {
		//non linear
		c.MT[i] = uint32((c.MT[i] ^ ((c.MT[i-1] ^ (c.MT[i-1] >> 30)) * uint32(1664525))) + initKey[j] + uint32(j))
		i++
		j++
		if i >= n {
			c.MT[0] = c.MT[n-1]
			i = 1
		}
		if j >= keyLength {
			j = 0
		}
	}

	for k = n - 1; k > 0; k-- {
		//non linear
		c.MT[i] = uint32((c.MT[i] ^ ((c.MT[i-1] ^ (c.MT[i-1] >> 30)) * uint32(1566083941))) - uint32(i))
		i++
		if i >= n {
			c.MT[0] = c.MT[n-1]
			i = 1
		}
	}

	c.MT[0] = uint32(0x80000000) /* MSB is 1; assuring non-zero initial array */
}

func main() {

}
