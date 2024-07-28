package ecies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"github.com/93ams/crypto/kdf"
)

type ECIES struct {
	Curve ecdh.Curve
	KDF   kdf.KDF
}

const nonceSize = 16
const gcmTagSize = 16

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func (ecies ECIES) Encrypt(pubkey *ecdh.PublicKey, msg []byte) ([]byte, error) {
	var ct bytes.Buffer
	ek, err := ecies.Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ct.Write(ek.PublicKey().Bytes())

	ss, err := ek.ECDH(pubkey)
	if err != nil {
		return nil, err
	}
	ss, err = ecies.KDF(ss)
	if err != nil {
		return nil, err
	}

	// AES encryption
	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}

	ct.Write(nonce)

	aesgcm, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)

	tag := ciphertext[len(ciphertext)-aesgcm.NonceSize():]
	ct.Write(tag)
	ciphertext = ciphertext[:len(ciphertext)-len(tag)]
	ct.Write(ciphertext)

	return ct.Bytes(), nil
}

// Decrypt decrypts a passed message with a receiver private key, returns plaintext or decryption error
func (ecies ECIES) Decrypt(privkey *ecdh.PrivateKey, msg []byte) ([]byte, error) {
	pkLen := len(privkey.PublicKey().Bytes())
	// Message cannot be less than length of public key (65) + nonce (16) + tag (16)
	if len(msg) <= (pkLen + nonceSize + gcmTagSize) {
		return nil, fmt.Errorf("invalid length of message")
	}
	// Ephemeral sender public key
	ek, err := ecies.Curve.NewPublicKey(msg[:pkLen])
	if err != nil {
		return nil, err
	}
	// Shift message
	msg = msg[pkLen:]

	// Derive shared secret
	ss, err := privkey.ECDH(ek)
	if err != nil {
		return nil, err
	}
	ss, err = ecies.KDF(ss)
	if err != nil {
		return nil, err
	}

	// AES decryption part
	nonce, tag := msg[:nonceSize], msg[nonceSize:nonceSize+gcmTagSize]

	// Create Golang-accepted ciphertext
	ciphertext := bytes.Join([][]byte{msg[nonceSize+gcmTagSize:], tag}, nil)

	block, err := aes.NewCipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, fmt.Errorf("cannot create gcm cipher: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}
