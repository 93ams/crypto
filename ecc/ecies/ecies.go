package ecies

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

type Cipher func([]byte) (cipher.AEAD, error)
type KDF func([]byte) ([]byte, error)

type PublicKey interface {
	Bytes() []byte
}
type PrivateKey[PubKey PublicKey] interface {
	ECDH(PubKey) ([]byte, error)
	PublicKey() PubKey
	Bytes() []byte
}
type Curve[PubKey PublicKey, PrvKey PrivateKey[PubKey]] interface {
	GenerateKey(io.Reader) (PrvKey, error)
	NewPublicKey([]byte) (PubKey, error)
}

type ECIES[PubKey PublicKey, PrvKey PrivateKey[PubKey]] struct {
	Curve  Curve[PubKey, PrvKey]
	Cipher Cipher
	KDF    KDF
}

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func (ecies ECIES[PubKey, PrvKey]) Encrypt(pubkey PubKey, msg []byte) ([]byte, error) {
	ek, err := ecies.Curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ss, err := ek.ECDH(pubkey)
	if err != nil {
		return nil, err
	}
	var secret bytes.Buffer
	secret.Write(ek.PublicKey().Bytes())
	secret.Write(ss)
	ss, err = ecies.KDF(secret.Bytes())
	if err != nil {
		return nil, err
	}
	c, err := ecies.Cipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create cipher: %w", err)
	}
	nonceSize := c.NonceSize()
	tagSize := c.Overhead()

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}

	ciphertext := c.Seal(nil, nonce, msg, nil)

	// other languages need tag+msg
	var ct bytes.Buffer
	ct.Write(ek.PublicKey().Bytes())
	ct.Write(nonce)
	ct.Write(ciphertext[len(ciphertext)-tagSize:])
	ct.Write(ciphertext[:len(ciphertext)-tagSize])

	return ct.Bytes(), nil
}

// Decrypt decrypts a passed message with a receiver private key, returns plaintext or decryption error
func (ecies ECIES[PubKey, PrvKey]) Decrypt(privkey PrvKey, msg []byte) ([]byte, error) {
	pkLen := len(privkey.PublicKey().Bytes())
	ek, err := ecies.Curve.NewPublicKey(msg[:pkLen])
	if err != nil {
		return nil, err
	}
	ss, err := privkey.ECDH(ek)
	if err != nil {
		return nil, err
	}
	var secret bytes.Buffer
	secret.Write(ek.Bytes())
	secret.Write(ss)
	ss, err = ecies.KDF(secret.Bytes())
	if err != nil {
		return nil, err
	}
	c, err := ecies.Cipher(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create cipher: %w", err)
	}
	msg = msg[pkLen:]
	tagSize := c.Overhead()
	nonceSize := c.NonceSize()

	// Golang needs msg+tag
	return c.Open(nil, msg[:nonceSize], bytes.Join([][]byte{
		msg[nonceSize+tagSize:],
		msg[nonceSize : nonceSize+tagSize],
	}, nil), nil)
}
