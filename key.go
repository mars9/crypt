package crypt

import (
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

type Key interface {
	// Derive returns the AES key and HMAC-SHA key, for the given password,
	// salt combination.
	Derive(salt []byte) (aesKey, hmacKey []byte)

	// Size returns the key-size. Key-size should either 16, 24, or 32 to
	// select AES-128, AES-192, or AES-256.
	Size() int

	// Reset resets/flushes the key.
	Reset()
}

type Pbkdf2Key struct {
	password []byte
	size     int
}

func NewPbkdf2Key(password []byte, size int) Pbkdf2Key {
	return Pbkdf2Key{password: password, size: size}
}

func (k Pbkdf2Key) Derive(salt []byte) (aesKey, hmacKey []byte) {
	key := pbkdf2.Key(k.password, salt, 4096, 2*k.size, sha1.New)
	aesKey = key[:k.size]
	hmacKey = key[k.size:]
	return aesKey, hmacKey
}

func (k Pbkdf2Key) Size() int { return k.size }

func (k Pbkdf2Key) Reset() {
	for i := range k.password {
		k.password[i] = 0
	}
}

type ScryptKey struct {
	password []byte
	size     int
}

func NewScryptKey(password []byte, size int) ScryptKey {
	return ScryptKey{password: password, size: size}
}

func (k ScryptKey) Derive(salt []byte) (aesKey, hmacKey []byte) {
	key, err := scrypt.Key(k.password, salt, 16384, 8, 1, 2*k.size)
	if err != nil {
		panic(err)
	}

	aesKey = key[:k.size]
	hmacKey = key[k.size:]
	return aesKey, hmacKey
}

func (k ScryptKey) Size() int { return k.size }

func (k ScryptKey) Reset() {
	for i := range k.password {
		k.password[i] = 0
	}
}
