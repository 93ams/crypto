package secp256k1

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// NewPublicKey decodes public key raw bytes and returns PublicKey instance;
// Supports both compressed and uncompressed public keys
func NewPublicKey(b []byte) (*PublicKey, error) {
	curve := secp256k1.S256()

	switch b[0] {
	case 0x02, 0x03:
		if len(b) != 33 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		x := new(big.Int).SetBytes(b[1:])
		var ybit uint
		switch b[0] {
		case 0x02:
			ybit = 0
		case 0x03:
			ybit = 1
		}

		if x.Cmp(curve.Params().P) >= 0 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		// y^2 = x^3 + b
		// y   = sqrt(x^3 + b)
		var y, x3b big.Int
		x3b.Mul(x, x)
		x3b.Mul(&x3b, x)
		x3b.Add(&x3b, curve.Params().B)
		x3b.Mod(&x3b, curve.Params().P)
		if z := y.ModSqrt(&x3b, curve.Params().P); z == nil {
			return nil, fmt.Errorf("cannot parse public key")
		}

		if y.Bit(0) != ybit {
			y.Sub(curve.Params().P, &y)
		}
		if y.Bit(0) != ybit {
			return nil, fmt.Errorf("incorrectly encoded X and Y bit")
		}

		return &PublicKey{
			Curve: curve,
			X:     x,
			Y:     &y,
		}, nil
	case 0x04:
		if len(b) != 65 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		x := new(big.Int).SetBytes(b[1:33])
		y := new(big.Int).SetBytes(b[33:])

		if x.Cmp(curve.Params().P) >= 0 || y.Cmp(curve.Params().P) >= 0 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		x3 := new(big.Int).Sqrt(x).Mul(x, x)
		if t := new(big.Int).Sqrt(y).Sub(y, x3.Add(x3, curve.Params().B)); t.IsInt64() && t.Int64() == 0 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		return &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil
	default:
		return nil, fmt.Errorf("cannot parse public key")
	}
}

// Bytes returns public key raw bytes;
// Could be optionally compressed by dropping Y part
func (k *PublicKey) Bytes() []byte {
	l := len(k.Curve.Params().P.Bytes())
	return bytes.Join([][]byte{{0x04},
		zeroPad(k.X.Bytes(), l),
		zeroPad(k.Y.Bytes(), l),
	}, nil)
}

func (k *PublicKey) Compressed() []byte {
	l := len(k.Curve.Params().P.Bytes())
	x := zeroPad(k.X.Bytes(), l)
	// If odd
	if k.Y.Bit(0) != 0 {
		return bytes.Join([][]byte{{0x03}, x}, nil)
	}
	// If even
	return bytes.Join([][]byte{{0x02}, x}, nil)
}

func zeroPad(b []byte, length int) []byte {
	if len(b) > length {
		panic("bytes too long")
	}
	if len(b) < length {
		b = append(make([]byte, length-len(b)), b...)
	}
	return b
}
