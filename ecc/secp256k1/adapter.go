package secp256k1

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"io"
)

type Curve struct {
}

func (Curve) GenerateKey(r io.Reader) (PrivateKey, error) {
	key, err := secp256k1.GeneratePrivateKeyFromRand(r)
	if err != nil {
		return PrivateKey{}, err
	}
	return PrivateKey{key}, nil
}
func (Curve) NewPublicKey(b []byte) (PublicKey, error) {
	key, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey{key}, nil
}

type PublicKey struct {
	*secp256k1.PublicKey
}

func (k PublicKey) Bytes() []byte {
	return k.PublicKey.SerializeUncompressed()
}

type PrivateKey struct {
	*secp256k1.PrivateKey
}

func (k PrivateKey) PublicKey() PublicKey {
	return PublicKey{k.PubKey()}
}

func (k PrivateKey) ECDH(pub PublicKey) ([]byte, error) {
	return secp256k1.GenerateSharedSecret(k.PrivateKey, pub.PublicKey), nil
}
