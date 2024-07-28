package ecies_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"github.com/93ams/crypto/ecc/ecies"
	"github.com/93ams/crypto/kdf"
	"github.com/stretchr/testify/require"
	"testing"
)

var salt = []byte("saltyboy")

func TestNIST_H256(t *testing.T) {
	for _, df := range []kdf.KDF{
		kdf.HKDF(salt, nil, 32, sha256.New),
		kdf.PBKDF2(salt, 4096, 32, sha256.New),
		kdf.Scrypt(salt, 32768, 8, 1, 32),
	} {
		for _, curve := range []ecdh.Curve{
			ecdh.P256(),
			ecdh.P384(),
			ecdh.P521(),
			ecdh.X25519(),
		} {
			e := ecies.ECIES{
				Curve: curve,
				KDF:   df,
			}
			pk, err := curve.GenerateKey(rand.Reader)
			require.NoError(t, err)

			expected := []byte("hello")

			encrypted, err := e.Encrypt(pk.PublicKey(), expected)
			require.NoError(t, err)

			actual, err := e.Decrypt(pk, encrypted)
			require.NoError(t, err)

			require.Equal(t, expected, actual)
		}
	}
}
