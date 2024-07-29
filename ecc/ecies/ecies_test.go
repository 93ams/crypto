package ecies_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/93ams/crypto/aead"
	"github.com/93ams/crypto/ecc/ecies"
	"github.com/93ams/crypto/ecc/secp256k1"
	"github.com/93ams/crypto/kdf"
	ecies2 "github.com/ecies/go/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
	"testing"
)

func TestECDH(t *testing.T) {
	for _, aeas := range []ecies.Cipher{
		aead.GCM(12),
		aead.GCM(16),
		chacha20poly1305.New,
		chacha20poly1305.NewX,
	} {
		for _, df := range []ecies.KDF{
			kdf.HKDF(nil, nil, 32, sha256.New),
			kdf.PBKDF2(nil, 4096, 32, sha256.New),
			kdf.Scrypt(nil, 32768, 8, 1, 32),
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

				expected := []byte("hello world!")

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
		//aead.GCM(12),
		aead.GCM(16),
		//chacha20poly1305.New,
		//chacha20poly1305.NewX,
	} {
		for _, df := range []ecies.KDF{
			kdf.HKDF(nil, nil, 32, sha256.New),
			//kdf.PBKDF2(nil, 4096, 32, sha256.New),
			//kdf.Scrypt(nil, 32768, 8, 1, 32),
		} {
			curve := secp256k1.Curve{}
			e := ecies.ECIES[*secp256k1.PublicKey, *secp256k1.PrivateKey]{
				Cipher: aeas,
				Curve:  curve,
				KDF:    df,
			}
			prv, pub, err := secp256k1.NewPemPair()
			require.NoError(t, err)

			privateKeyBytes, err := secp256k1.UnmarshalPrivateKey(prv)
			require.NoError(t, err)
			publicKeyBytes, err := secp256k1.UnmarshalPublicKey(pub)
			require.NoError(t, err)
			publicKey, err := secp256k1.NewPublicKey(publicKeyBytes)
			require.NoError(t, err)
			privateKey := secp256k1.NewPrivateKey(privateKeyBytes)
			require.Equal(t, publicKeyBytes, privateKey.Public.Bytes())

			log.Println(hex.EncodeToString(privateKey.Bytes()))

			expected := []byte("hello world!")

			encrypted, err := e.Encrypt(publicKey, expected)
			require.NoError(t, err)

			publicKey2, err := ecies2.NewPublicKeyFromBytes(publicKeyBytes)
			require.NoError(t, err)
			require.Equal(t, hex.EncodeToString(publicKey.Bytes()), publicKey2.Hex(false))

			log.Println(base64.StdEncoding.EncodeToString(encrypted))
			actual, err := e.Decrypt(privateKey, encrypted)
			require.NoError(t, err)
			require.Equal(t, expected, actual)
		}
	}
}
