package ecdh

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
    "github.com/liasica/go-encryption/hexutil"
)

// GenerateKey generate ecdh private and public keys
func GenerateKey() (priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey, err error) {
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

// ShareKey exchange ecdh key from compressed public
func ShareKey(pubHex, privHex string) (shared string, err error) {
    var pubOthers *ecdsa.PublicKey
    pubOthers, err = PublicKeyDecode(pubHex)
    if err != nil {
        return
    }

    var priv *ecdsa.PrivateKey
    priv, err = PrivateKeyDecode(privHex)
    if err != nil {
        return
    }

    a, _ := pubOthers.Curve.ScalarMult(pubOthers.X, pubOthers.Y, priv.D.Bytes())
    b := sha256.Sum256(a.Bytes())

    shared = hexutil.Encode(b[:])

    return
}
