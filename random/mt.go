package random

/* CryptMT Stream Cipher, Relying Mersenne Twister */
/* By Hagita-Matsumoto-Nishimura-Saito */
/* MT included */
/* 2005/04/16 */

// Ctx is context
type Ctx struct {
	mt    [624]uint32 // MT state
	mti   int         // index into MT
	accum uint32      // Accumulator
}

///////////////////////////
// CryptMT v1.0 Implementation
// By Hagita-Matsumoto-Nishimura-Saito

// MT has period 2^19937-1 and uniform equidistribution property upto 623 dimension.

// Period parameters :

// N is GF(2) linear generator's state size in words (624*32 = 19968 bits ~= 19937+32). 32 bits discarded.
// N is max dimensions MT has equidistribution or in other words
// N is period parameter for MT's state size in words(32bits)
const N = 624

// M is period parameter represents the starting word of GF(2) in MT's state
const M = 397
const matrixA uint32 = 0x9908B0DF   // constant vector a
const upperMask uint32 = 0x80000000 // most significant w-r bits
const lowerMask uint32 = 0x7FFFFFFF // least significant r bits

// NewSeeded initializes mt[N] with a seed
func NewSeeded(s uint32) *Ctx {
	c := new(Ctx)
	c.mt[0] = s & uint32(0xFFFFFFFF)
	for c.mti = 1; c.mti < N; c.mti++ {
		c.mt[c.mti] = uint32(uint32(1812433253)*(c.mt[c.mti-1]^(c.mt[c.mti-1]>>30)) + uint32(c.mti))
		/* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
		/* In the previous versions, MSBs of the seed affect   */
		/* only MSBs of the array mt[].                        */
		/* 2002/01/09 modified by Makoto Matsumoto             */
	}

	//c.warmup()
	return c
}

// NewArraySeeded initializes MT with initKey array (recommended size core.N)
//
// originally was called InitByArray
// initKey is the array for initializing keys
// slight change for C++, 2004/2/26
func NewArraySeeded(initKey []uint32) *Ctx {
	var i, j, k int
	c := NewSeeded(uint32(19650218))
	i = 1
	j = 0

	keyLength := len(initKey)
	k = keyLength
	if keyLength < N {
		k = N
	}

	for ; k > 0; k-- {
		//non linear
		c.mt[i] = (c.mt[i] ^ ((c.mt[i-1] ^ (c.mt[i-1] >> 30)) * uint32(1664525))) +
			initKey[j] + uint32(j)
		i++
		j++
		if i >= N {
			c.mt[0] = c.mt[N-1]
			i = 1
		}
		if j >= keyLength {
			j = 0
		}
	}

	for k = N - 1; k > 0; k-- {
		//non linear
		c.mt[i] = (c.mt[i] ^ ((c.mt[i-1] ^ (c.mt[i-1] >> 30)) * uint32(1566083941))) -
			uint32(i)
		i++
		if i >= N {
			c.mt[0] = c.mt[N-1]
			i = 1
		}
	}

	c.mt[0] = uint32(0x80000000) // MSB is 1; assuring non-zero initial array
	return c
}

// Warmup idles 64 times
func (c *Ctx) Warmup() {
	c.accum = 1
	c.mt[0] |= uint32(0x80000000) // MSB is 1; assuring non-zero initial array
	c.mti = N + 1                 // mti==N+1 means mt[N] needs Blending/Initializing
	for i := 0; i < 64; i++ {     // warm up : idling 64 times
		c.SecureNext() // calling Secure version to account for accumulator Accum
	}
}

// Read reads up to len(p) bytes into p.
// It returns the number of bytes read (0 <= n <= len(p)) and any error encountered.
func Read(p []byte) (n int, err error) {
	return 0, nil
}

var mag01 = [2]uint32{uint32(0x0), matrixA}

// BlendInternalState generates whole array of random numbers in [0,0xffffffff]-interval
func (c *Ctx) BlendInternalState() {
	var y uint32

	////
	//// mag01[x] = x * MATRIX_A  for x=0,1
	////

	var kk int

	for kk = 0; kk < N-M; kk++ {
		y = (c.mt[kk] & upperMask) | (c.mt[kk+1] & lowerMask)
		c.mt[kk] = c.mt[kk+M] ^ (y >> 1) ^ mag01[y&uint32(0x1)]
	}
	for ; kk < N-1; kk++ {
		y = (c.mt[kk] & upperMask) | (c.mt[kk+1] & lowerMask)
		c.mt[kk] = c.mt[kk+(M-N)] ^ (y >> 1) ^ mag01[y&uint32(0x1)]
	}
	y = (c.mt[N-1] & upperMask) | (c.mt[0] & lowerMask)
	c.mt[N-1] = c.mt[M-1] ^ (y >> 1) ^ mag01[y&uint32(0x1)]

	c.mti = 0
	return
}

// NextWord to generate 32-bit random integer
// NOTE: Either use only NextWord or only SecureNext not both
func (c *Ctx) NextWord() uint32 {
	if c.mti >= N {
		c.BlendInternalState()
	}

	//no tampering
	ret := c.mt[c.mti]
	c.mti++
	return ret
}

// SecureNext generates secure next random byte
// NOTE: Either use only NextWord or only SecureNext not both
func (c *Ctx) SecureNext() byte {
	c.accum *= (c.NextWord() | 0x1)
	return byte(c.accum >> 24)
}

// DumpContext to
// func (c *Ctx) DumpContext() string { //TODEL
// 	s := "MT["
// 	for _, v := range c.mt[:16] {
// 		s = s + fmt.Sprintf("%8x ", v)
// 	}
// 	s = s + "]"
// 	return s
// }
