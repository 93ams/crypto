package ecies_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"github.com/93ams/crypto/aes"
	"github.com/93ams/crypto/ecc/ecies"
	"github.com/93ams/crypto/ecc/secp256k1"
	"github.com/93ams/crypto/kdf"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"testing"
)

var salt = []byte("saltyboy")

func TestECDH(t *testing.T) {
	for _, aeas := range []ecies.Cipher{
		aes.GCM(12),
		aes.GCM(16),
		aes.GCM(20),
		chacha20poly1305.New,
		chacha20poly1305.NewX,
	} {
		for _, df := range []ecies.KDF{
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
				e := ecies.ECIES[*ecdh.PublicKey, *ecdh.PrivateKey]{
					Cipher: aeas,
					Curve:  curve,
					KDF:    df,
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
}
func TestSecp256k1(t *testing.T) {
	for _, aeas := range []ecies.Cipher{
		aes.GCM(16),
		chacha20poly1305.New,
		chacha20poly1305.NewX,
	} {
		for _, df := range []ecies.KDF{
			kdf.HKDF(salt, nil, 32, sha256.New),
			kdf.PBKDF2(salt, 4096, 32, sha256.New),
			kdf.Scrypt(salt, 32768, 8, 1, 32),
		} {
			curve := secp256k1.Curve{}
			e := ecies.ECIES[secp256k1.PublicKey, secp256k1.PrivateKey]{
				Cipher: aeas,
				Curve:  curve,
				KDF:    df,
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
