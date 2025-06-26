package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"strings"
)

func AesCbcEncrypt(data, key, iv string) ([]byte, error) {

	keyArr := []byte(strings.TrimSpace(key))
	ivArr := []byte(iv)
	dataArr := []byte(data)

	block, err := aes.NewCipher(keyArr)
	if err != nil {
		return nil, err
	}

	dataArr = pkcs7Padding(dataArr, aes.BlockSize)

	mode := cipher.NewCBCEncrypter(block, ivArr)
	ciphertext := make([]byte, len(dataArr))
	mode.CryptBlocks(ciphertext, dataArr)

	return ciphertext, nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}
