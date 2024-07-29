package secp256k1

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
)

// PrivateKey is an instance of secp256k1 private key with nested public key
type PrivateKey struct {
	Public *PublicKey
	D      *big.Int
}

// NewPrivateKey decodes private key raw bytes, computes public key and returns PrivateKey instance
func NewPrivateKey(priv []byte) *PrivateKey {
	curve := secp256k1.S256()
	x, y := curve.ScalarBaseMult(priv)

	return &PrivateKey{
		Public: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(priv),
	}
}
func (k *PrivateKey) PublicKey() *PublicKey {
	return k.Public
}

// Bytes returns private key raw bytes
func (k *PrivateKey) Bytes() []byte {
	return k.D.Bytes()
}

func (k *PrivateKey) ECDH(pubkey *PublicKey) ([]byte, error) {
	ret := PublicKey{Curve: pubkey.Curve}
	ret.X, ret.Y = pubkey.Curve.ScalarMult(pubkey.X, pubkey.Y, k.D.Bytes())
	return ret.Bytes(), nil
}
