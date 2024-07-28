package ecies

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
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
}
type Curve[PubKey PublicKey, PrvKey PrivateKey[PubKey]] interface {
	GenerateKey(io.Reader) (PrvKey, error)
	NewPublicKey([]byte) (PubKey, error)
}

var _ PublicKey = (*ecdh.PublicKey)(nil)
var _ PrivateKey[*ecdh.PublicKey] = (*ecdh.PrivateKey)(nil)
var _ Curve[*ecdh.PublicKey, *ecdh.PrivateKey] = ecdh.Curve(nil)

type ECIES[PubKey PublicKey, PrvKey PrivateKey[PubKey]] struct {
	Curve  Curve[PubKey, PrvKey]
	Cipher Cipher
	KDF    KDF
}

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func (ecies ECIES[PubKey, PrvKey]) Encrypt(pubkey PubKey, msg []byte) ([]byte, error) {
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
	ct.Write(nonce)

	ciphertext := c.Seal(nil, nonce, msg, nil)

	tag := ciphertext[len(ciphertext)-tagSize:]
	ct.Write(tag)
	ciphertext = ciphertext[:len(ciphertext)-tagSize]
	ct.Write(ciphertext)

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
	ss, err = ecies.KDF(ss)
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
	return c.Open(nil, msg[:nonceSize], bytes.Join([][]byte{msg[nonceSize+tagSize:], msg[nonceSize : nonceSize+tagSize]}, nil), nil)
}
