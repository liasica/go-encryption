package rsa

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "errors"
)

const (
    MaxSize = 200
)

// Encrypt RSA encrypt to []byte (using public key)
func Encrypt(data, key []byte) (b []byte, err error) {
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
    pub, ok := dpub.(*rsa.PublicKey)
    if !ok {
        err = errors.New("RSA Key parse error")
        return
    }

    return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
}

// EncryptToBase64 RSA encrypt to base64 string (using public key)
func EncryptToBase64(data, key []byte) (b64 string, err error) {
    var b []byte
    b, err = Encrypt(data, key)
    if err != nil {
        return
    }
    b64 = base64.StdEncoding.EncodeToString(b)
    return
}

// Decrypt RSA decode bytes to bytes (using private key)
func Decrypt(b, key []byte) (data []byte, err error) {
    block, _ := pem.Decode(key)
    if block == nil {
        err = errors.New("RSA Key error")
        return
    }

    // parse private
    var priv *rsa.PrivateKey
    priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return
    }

    // decode data
    return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, b, nil)
}

// DecryptFromBase64 RSA decode base64 string to bytes (using private key)
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
