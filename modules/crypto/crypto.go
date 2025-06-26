package crypto

import (
	"hash"
	"io"
	"log"
	"math/big"

	pec256 "github.com/polarysfoundation/pec-256"
	pm256 "github.com/polarysfoundation/pm-256"
	"golang.org/x/crypto/hkdf"
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
