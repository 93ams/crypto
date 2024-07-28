package kdf

import (
	"fmt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"hash"
	"io"
)

type KDF func([]byte) ([]byte, error)

func HKDF(salt, info []byte, keyLen int, h func() hash.Hash) KDF {
	return func(secret []byte) (key []byte, err error) {
		key = make([]byte, keyLen)
		kdf := hkdf.New(h, secret, salt, info)
		if _, err := io.ReadFull(kdf, key); err != nil {
			return nil, fmt.Errorf("cannot read secret from HKDF reader: %w", err)
		}
		return key, nil
	}
}
func Scrypt(salt []byte, N, r, p, keyLen int) KDF {
	return func(secret []byte) ([]byte, error) {
		return scrypt.Key(secret, salt, N, r, p, keyLen)
	}
}
func PBKDF2(salt []byte, iter, keyLen int, h func() hash.Hash) KDF {
	return func(secret []byte) ([]byte, error) {
		return pbkdf2.Key(secret, salt, iter, keyLen, h), nil
	}
}
