package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func ParsePublicKey(key []byte) (pub *rsa.PublicKey, err error) {
	block, _ := pem.Decode(key)
	if block == nil {
		err = errors.New("RSA Key error")
		return
	}
	var dpub any
	dpub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}

	var ok bool
	pub, ok = dpub.(*rsa.PublicKey)
	if !ok {
		err = errors.New("RSA Key parse error")
	}

	return
}

func ParsePrivateKey(key []byte) (priv *rsa.PrivateKey, err error) {
	block, _ := pem.Decode(key)
	if block == nil {
		err = errors.New("RSA Key error")
		return
	}

	// parse private
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
