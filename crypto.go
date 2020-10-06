package crypto

// Crypto cryptography interface
type Crypto interface {
	// Hash make hash for data
	Hash(data string, algo HashAlgo) (string, error)
	// HashFilename make hashed filename for based on current timestamp
	HashFilename(filename string, algo HashAlgo) (string, error)
	// HashSize get hash size for algorithm
	// return -1 if invalid algo passed
	HashSize(algo HashAlgo) int
	// Check check data agains hash
	Check(data string, hash string, algo HashAlgo) (bool, error)
	// Encrypt data
	Encrypt(data []byte) ([]byte, error)
	// Decrypt data
	Decrypt(data []byte) ([]byte, error)
	// EncryptHEX data
	EncryptHEX(data []byte) (string, error)
	// DecryptHex data
	DecryptHex(hexString string) ([]byte, error)
	// EncryptBase64 data
	EncryptBase64(data []byte) (string, error)
	// DecryptBase64 data
	DecryptBase64(base64String string) ([]byte, error)
}
