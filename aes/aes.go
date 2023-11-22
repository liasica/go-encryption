// Copyright (C) liasica. 2022-present.
//
// Created at 2022-08-29
// Based on go-encryption by liasica, magicrolan@qq.com.

package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// Encrypt AES encrypt, CBC
func Encrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func EncryptToBase64(origData, key []byte) (b64 string, err error) {
	var b []byte
	b, err = Encrypt(origData, key)
	if err != nil {
		return
	}
	b64 = base64.StdEncoding.EncodeToString(b)
	return
}

// Decrypt AES decrypt
func Decrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func DecryptFromBase64(b64 string, key []byte) (data []byte, err error) {
	var b []byte
	b, err = base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return
	}

	// decode data
	data, err = Decrypt(b, key)
	if err != nil {
		return
	}
	return
}
