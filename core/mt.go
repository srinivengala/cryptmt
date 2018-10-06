package core

/* CryptMT Stream Cipher, Relying Mersenne Twister */
/* By Hagita-Matsumoto-Nishimura-Saito */
/* MT included */
/* 2005/04/16 */

// MaxKeySize is max key size supported by this cipher
const MaxKeySize = 2048

// CmtKeySize to iterate through key sizes
func CmtKeySize(i int) int {
	return 128 + i*32
}

// MaxIVSize is max IV size supported
const MaxIVSize = 2048

func cmtIVSize(i int) int {
	return 128 + i*32
}

// Ctx is context
type Ctx struct {
	Keysize uint32 // size in bits
	IVSize  uint32 // size in bits
	Key     [MaxKeySize / 8]uint8
	IV      [MaxIVSize / 8]uint8

	MT    [624]uint32
	Mti   int
	Accum uint32
}

///////////////////////////
// CryptMT v1.0 Implementation
// By Hagita-Matsumoto-Nishimura-Saito

// Period parameters
const n = 624
const m = 397
const matrixA uint32 = 0x9908B0DF   // constant vector a
const upperMask uint32 = 0x80000000 // most significant w-r bits
const lowerMask uint32 = 0x7FFFFFFF // least significant r bits

// initializes mt[N] with a seed
func initGenrand(c *Ctx, s uint32) {
	c.MT[0] = s & uint32(0xFFFFFFFF)
	for c.Mti = 1; c.Mti < n; c.Mti++ {
		c.MT[c.Mti] = uint32(uint32(1812433253)*(c.MT[c.Mti-1]^(c.MT[c.Mti-1]>>30)) + uint32(c.Mti))
		/* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
		/* In the previous versions, MSBs of the seed affect   */
		/* only MSBs of the array mt[].                        */
		/* 2002/01/09 modified by Makoto Matsumoto             */
	}
}

// InitByArray to initialize with array-length
// init_key is the array for initializing keys
// key_length is its length
// slight change for C++, 2004/2/26
func InitByArray(c *Ctx, initKey []uint32, keyLength uint) {
	var i, j, k int
	initGenrand(c, uint32(19650218))
	i = 1
	j = 0

	k = int(keyLength)
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
		if j >= int(keyLength) {
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

var mag01 = [2]uint32{uint32(0x0), matrixA}

/* generates whole array of random numbers in [0,0xffffffff]-interval */
func genrandWholeArray(c *Ctx) {
	var y uint32

	/* mag01[x] = x * MATRIX_A  for x=0,1 */

	var kk int

	for kk = 0; kk < n-m; kk++ {
		y = (c.MT[kk] & upperMask) | (c.MT[kk+1] & lowerMask)
		c.MT[kk] = c.MT[kk+m] ^ (y >> 1) ^ mag01[y&uint32(0x1)]
	}
	for ; kk < n-1; kk++ {
		y = (c.MT[kk] & upperMask) | (c.MT[kk+1] & lowerMask)
		c.MT[kk] = c.MT[kk+(m-n)] ^ (y >> 1) ^ mag01[y&uint32(0x1)]
	}
	y = (c.MT[n-1] & upperMask) | (c.MT[0] & lowerMask)
	c.MT[n-1] = c.MT[m-1] ^ (y >> 1) ^ mag01[y&uint32(0x1)]

	c.Mti = 0
	return
}

// GenrandInt32 to generate 32-bit random integer
func GenrandInt32(c *Ctx) uint32 {
	if c.Mti >= n {
		genrandWholeArray(c)
	}

	//no tampering
	ret := c.MT[c.Mti]
	c.Mti++
	return ret
}
