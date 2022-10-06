package rsa

import (
    "bytes"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
)

func split(buf []byte, lim int) [][]byte {
    var chunk []byte
    chunks := make([][]byte, 0, len(buf)/lim+1)
    for len(buf) >= lim {
        chunk, buf = buf[:lim], buf[lim:]
        chunks = append(chunks, chunk)
    }
    if len(buf) > 0 {
        chunks = append(chunks, buf[:])
    }
    return chunks
}

func EncryptUsePublicKey(data []byte, pub *rsa.PublicKey) (b []byte, err error) {
    // chunks encrypt
    hash := sha256.New()
    maxlen := pub.Size() - hash.Size()*2 - 2
    chunks := split(data, maxlen)
    buffer := &bytes.Buffer{}
    for _, chunk := range chunks {
        var out []byte
        out, err = rsa.EncryptOAEP(hash, rand.Reader, pub, chunk, nil)
        if err != nil {
            return
        }
        buffer.Write(out)
    }

    b = buffer.Bytes()
    return
}

// Encrypt RSA encrypt to []byte (using public key)
func Encrypt(data, key []byte) (b []byte, err error) {
    var pub *rsa.PublicKey
    pub, err = ParsePublicKey(key)
    if err != nil {
        return
    }

    return EncryptUsePublicKey(data, pub)
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

func DecryptUsePrivateKey(b []byte, priv *rsa.PrivateKey) (data []byte, err error) {
    // chunks decrypt
    maxlen := priv.PublicKey.Size()
    chunks := split(b, maxlen)
    buffer := &bytes.Buffer{}
    for _, chunk := range chunks {
        var out []byte
        out, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, chunk, nil)
        if err != nil {
            return
        }
        buffer.Write(out)
    }

    data = buffer.Bytes()
    return
}

// Decrypt RSA decode bytes to bytes (using private key)
func Decrypt(b, key []byte) (data []byte, err error) {
    var priv *rsa.PrivateKey
    priv, err = ParsePrivateKey(key)
    if err != nil {
        return
    }

    return DecryptUsePrivateKey(b, priv)
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
