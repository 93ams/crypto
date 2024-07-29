package secp256k1

import (
	"crypto/elliptic"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"io"
	"math/big"
)

type Curve struct {
}

func (Curve) GenerateKey(r io.Reader) (*PrivateKey, error) {
	curve := secp256k1.S256()
	p, x, y, err := elliptic.GenerateKey(curve, r)
	if err != nil {
		return nil, fmt.Errorf("cannot generate key pair: %w", err)
	}
	return &PrivateKey{
		Public: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(p),
	}, nil
}
func (Curve) NewPublicKey(b []byte) (*PublicKey, error) {
	return NewPublicKey(b)
}
