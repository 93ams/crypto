package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func GCM(nonceSize int) func([]byte) (cipher.AEAD, error) {
	return func(secret []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(secret)
		if err != nil {
			return nil, fmt.Errorf("cannot create new gcm cipher block: %w", err)
		}
		return cipher.NewGCMWithNonceSize(block, nonceSize)
	}
}
