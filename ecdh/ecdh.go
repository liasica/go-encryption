package ecdh

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/liasica/go-encryption/hexutil"
)

// Generate ecdsa private and public keys
func Generate() (priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, err error) {
	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	pub = &priv.PublicKey
	return
}

// PrivateKeyEncode ECDH private key encode to hex string
func PrivateKeyEncode(priv *ecdsa.PrivateKey) (str string, err error) {
	var b []byte
	b, err = x509.MarshalECPrivateKey(priv)
	if err != nil {
		return
	}
	str = hexutil.Encode(b)
	return
}

// PrivateKeyDecode ECDH private key decode from hex string
func PrivateKeyDecode(str string) (priv *ecdsa.PrivateKey, err error) {
	var b []byte
	b, err = hexutil.Decode(str)
	if err != nil {
		return
	}
	return x509.ParseECPrivateKey(b)
}

// PublicKeyEncode ECDH public key encode to hex string
func PublicKeyEncode(pub *ecdsa.PublicKey) string {
	return hexutil.Encode(elliptic.MarshalCompressed(elliptic.P256(), pub.X, pub.Y))
}

// PublicKeyDecode ECDH public key decode from hex string
func PublicKeyDecode(str string) (pub *ecdsa.PublicKey, err error) {
	var b []byte
	b, err = hexutil.Decode(str)
	if err != nil {
		return
	}
	c := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(c, b)
	pub = &ecdsa.PublicKey{
		Curve: c,
		X:     x,
		Y:     y,
	}
	return
}

// GenerateShared generate shared key from remote public key and self's private key
func GenerateShared(remotePublicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) (key []byte, err error) {
	var selfKey *ecdh.PrivateKey
	selfKey, err = privateKey.ECDH()
	if err != nil {
		return
	}

	var remote *ecdh.PublicKey
	remote, err = remotePublicKey.ECDH()
	if err != nil {
		return
	}

	return selfKey.ECDH(remote)
}
