package crypto

import pec256 "github.com/polarysfoundation/pec-256"

type SecurityKey struct {
	PubKey  pec256.PubKey
	PrivKey pec256.PrivKey
}

func NewSecurityKey() (SecurityKey, error) {
	priv, pub, _, err := pec256.PEC256().GenerateKeyPair()
	if err != nil {
		return SecurityKey{}, err
	}

	return SecurityKey{
		PubKey:  pub,
		PrivKey: priv,
	}, nil
}

