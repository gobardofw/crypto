package crypto

// HashAlgo available hash algo list
type HashAlgo int

const (
	// MD4 hash algorithm
	MD4 HashAlgo = iota
	// MD5 hash algorithm
	MD5
	// SHA1 hash algorithm
	SHA1
	// SHA256 hash algorithm
	SHA256
	// SHA256224 hash algorithm
	SHA256224
	// SHA384 hash algorithm
	SHA384
	// SHA512 hash algorithm
	SHA512
	// SHA512224 hash algorithm
	SHA512224
	// SHA512256 hash algorithm
	SHA512256
	// SHA3224 hash algorithm
	SHA3224
	// SHA3256 hash algorithm
	SHA3256
	// SHA3384 hash algorithm
	SHA3384
	// SHA3512 hash algorithm
	SHA3512
	// KECCAK256 hash algorithm
	KECCAK256
	// KECCAK512 hash algorithm
	KECCAK512
)
