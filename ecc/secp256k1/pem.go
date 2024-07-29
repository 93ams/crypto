package secp256k1

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
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
	if key, err := (Curve{}).GenerateKey(rand.Reader); err != nil {
		return nil, nil, err
	} else if prv, err = MarshalPrivateKey(key); err != nil {
		return nil, nil, fmt.Errorf("export priv key: %v", err)
	} else if pub, err = MarshalPublicKey(key.Public); err != nil {
		return nil, nil, fmt.Errorf("generating public pem: %s", err)
	}
	return prv, pub, nil
}

func MarshalPrivateKey(priv *PrivateKey) ([]byte, error) {
	privBytes, err := asn1.Marshal(ecPrivateKey{
		Version:       1,
		NamedCurveOID: oid,
		PrivateKey:    priv.Bytes(),
		PublicKey:     asn1.BitString{Bytes: priv.Public.Bytes()},
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

func UnmarshalPrivateKey(priv []byte) ([]byte, error) {
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
	return privKey.PrivateKey, nil
}

func MarshalPublicKey(pub *PublicKey) ([]byte, error) {
	publicKeyBytes := pub.Bytes()
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

func UnmarshalPublicKey(pub []byte) ([]byte, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, fmt.Errorf("key not found")
	}
	var pubKey pkixPublicKey
	if _, err := asn1.Unmarshal(block.Bytes, &pubKey); err != nil {
		return nil, fmt.Errorf("x509: failed to parse EC public key: " + err.Error())
	}
	return pubKey.BitString.Bytes, nil
}
