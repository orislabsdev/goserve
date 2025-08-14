package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"

	pec256 "github.com/polarysfoundation/pec-256"
	pm256 "github.com/polarysfoundation/pm-256"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

var c = pec256.PEC256()

func GenerateKey() (pec256.PrivKey, pec256.PubKey) {
	priv, pub, _, err := c.GenerateKeyPair()
	if err != nil {
		log.Printf("error generating keys: %v", err)
		panic("error creating new keypair")
	}

	return priv, pub
}

func LoadSecurityKey(path string, passphrase []byte) (pec256.PrivKey, pec256.PubKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pec256.PrivKey{}, pec256.PubKey{}, fmt.Errorf("failed to read key file: %w", err)
	}

	keyData, err := decryptWithPassphrase(passphrase, data)
	if err != nil {
		return pec256.PrivKey{}, pec256.PubKey{}, fmt.Errorf("failed to decrypt key: %w", err)
	}

	privKeyBytes := keyData[:32]

	if len(privKeyBytes) != 32 {
		return pec256.PrivKey{}, pec256.PubKey{}, fmt.Errorf("invalid private key length: expected 32, got %d", len(privKeyBytes))
	}

	var privKey pec256.PrivKey
	copy(privKey[:], privKeyBytes)

	pubKey := GetPubKey(privKey)

	return privKey, pubKey, nil
}

// SaveSecurityKey saves the private key from a SecurityKey to a file, hex-encoded.
func SaveSecurityKey(path string, key SecurityKey, passphrase []byte) error {
	buf := make([]byte, 32)
	copy(buf, key.PrivKey[:])

	data, err := encryptWithPassphrase(passphrase, buf)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	// We use 0600 permissions to ensure only the owner can read/write the key file.
	err = os.WriteFile(filepath.Join(path, "keys.key"), data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

func Sign(data []byte, priv pec256.PrivKey) (*big.Int, *big.Int, error) {
	return c.Sign(data, priv.BigInt())
}

func GenerateSharedKey(priv pec256.PrivKey) pec256.SharedKey {
	return c.SharedKey(priv)
}

func Verify(data []byte, r, s *big.Int, pub pec256.PubKey) (bool, error) {
	return c.Verify(data, r, s, pub.BigInt())
}

func NewPM256() hash.Hash {
	return pm256.New256()
}

func GetPubKey(priv pec256.PrivKey) pec256.PubKey {
	pub, _ := c.GetPubKey(priv)

	if !c.IsValidPubKey(pub.BigInt()) {
		panic("invalid pubkey")
	}

	return pub
}

func DeriveAESKey(secret []byte) ([]byte, error) {
	hk := hkdf.New(NewPM256, secret, nil, nil)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptWithPassphrase encrypts data using a key derived from a passphrase.
// It uses Scrypt for key derivation and AES-GCM for authenticated encryption.
// The output format is: salt (32 bytes) | nonce (12 bytes) | ciphertext.
func encryptWithPassphrase(passphrase, data []byte) ([]byte, error) {
	// 1. Generate a random salt. A salt is crucial for preventing rainbow table attacks.
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// 2. Derive a 32-byte key from the passphrase and salt using Scrypt.
	// Scrypt is a password-based key derivation function that is designed to be
	// computationally and memory-intensive to protect against brute-force attacks.
	// N=32768, r=8, p=1 are common recommended values.
	key, err := scrypt.Key(passphrase, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key from passphrase: %w", err)
	}

	// 3. Encrypt the data using AES-GCM.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// 4. Generate a random nonce. A nonce must be unique for each encryption with the same key.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// 5. Seal (encrypt) the data.
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	// 6. Prepend salt and nonce to the ciphertext for use during decryption.
	encryptedData := append(salt, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	return encryptedData, nil
}

// DecryptWithPassphrase decrypts data that was encrypted with EncryptWithPassphrase.
func decryptWithPassphrase(passphrase, encryptedData []byte) ([]byte, error) {
	const saltSize = 32
	const nonceSize = 12 // AES-GCM standard nonce size

	if len(encryptedData) < saltSize+nonceSize {
		return nil, fmt.Errorf("encrypted data is too short to contain salt and nonce")
	}

	salt := encryptedData[:saltSize]
	nonce := encryptedData[saltSize : saltSize+nonceSize]
	ciphertext := encryptedData[saltSize+nonceSize:]

	key, err := scrypt.Key(passphrase, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key from passphrase: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// This error is often returned for an incorrect passphrase or tampered ciphertext.
		return nil, fmt.Errorf("failed to decrypt data (check passphrase or data integrity): %w", err)
	}

	return plaintext, nil
}

func GenerateAuthToken(pub pec256.PubKey) (string, error) {
	if pub.BigInt() == nil {
		return "", fmt.Errorf("public key is nil")
	}

	h := NewPM256()
	h.Write(pub.BigInt().Bytes())
	token := fmt.Sprintf("%x", h.Sum(nil))
	return token, nil
}
