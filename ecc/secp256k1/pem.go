package secp256k1

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
)

var oid = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

func NewPemPair() (prv []byte, pub []byte, err error) {
	if key, err := secp256k1.GeneratePrivateKey(); err != nil {
		return nil, nil, err
	} else if prv, err = MarshalPrivateKey(key); err != nil {
		return nil, nil, fmt.Errorf("export priv key: %v", err)
	} else if pub, err = MarshalPublicKey(key.PubKey()); err != nil {
		return nil, nil, fmt.Errorf("generating public pem: %s", err)
	}
	return prv, pub, nil
}

func MarshalPrivateKey(priv *secp256k1.PrivateKey) ([]byte, error) {
	key := priv.ToECDSA()

	privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	privBytes, err := asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(privateKey),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
	if err != nil {
		return nil, fmt.Errorf("marshalling EC private key: %s", err)
	}

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		},
	), nil
}

func UnmarshalPrivateKey(priv []byte) (*secp256k1.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, fmt.Errorf("key not found")
	}
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(block.Bytes, &privKey); err != nil {
		return nil, fmt.Errorf("x509: failed to parse EC private key: " + err.Error())
	} else if privKey.Version != 1 {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}
	curveOrder := secp256k1.S256().Params().N
	if new(big.Int).SetBytes(privKey.PrivateKey).Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("x509: invalid elliptic curve private key value")
	}
	for len(privKey.PrivateKey) > (curveOrder.BitLen()+7)/8 {
		if privKey.PrivateKey[0] != 0 {
			return nil, fmt.Errorf("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}
	return secp256k1.PrivKeyFromBytes(privKey.PrivateKey), nil
}

func MarshalPublicKey(pub *secp256k1.PublicKey) ([]byte, error) {
	pubECDH := pub.ToECDSA()
	publicKeyBytes := elliptic.Marshal(pubECDH.Curve, pubECDH.X, pubECDH.Y)
	paramBytes, err := asn1.Marshal(oid)
	if err != nil {
		return nil, err
	}
	pubBytes, err := asn1.Marshal(pkixPublicKey{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: oid,
			Parameters: asn1.RawValue{
				FullBytes: paramBytes,
			},
		},
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PUBLIC KEY",
			Bytes: pubBytes,
		},
	), nil
}

func UnmarshalPublicKey(pub []byte) (*secp256k1.PublicKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, fmt.Errorf("key not found")
	}
	var pubKey pkixPublicKey
	if _, err := asn1.Unmarshal(block.Bytes, &pubKey); err != nil {
		return nil, fmt.Errorf("x509: failed to parse EC public key: " + err.Error())
	}
	return secp256k1.ParsePubKey(pubKey.BitString.Bytes)
}
