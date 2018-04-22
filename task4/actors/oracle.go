package actors

import (
	"crypto/rand"
	"crypto/aes"
	"crypto/cipher"
)

func RandomBytes(dst []byte) {
	_, err := rand.Read(dst)
	if err != nil {
		panic(err)
	}
}

func Encrypt(key, message, dst, iv []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(dst, message)
}

func Decrypt(key, ciphered, dst, iv []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(dst, ciphered)
}
