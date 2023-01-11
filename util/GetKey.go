package util

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
)

func LoadPrivateKey(pemPath string) *rsa.PrivateKey {

	key, _ := ioutil.ReadFile(pemPath)
	block, _ := pem.Decode(key)
	if block == nil {
		return nil
	}
	p, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil
	} else {
		pk := p.(*rsa.PrivateKey)
		keyBytes, err := x509.MarshalPKCS8PrivateKey(pk)
		if err != nil {
			return pk
		}
		pemBlock := pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		}
		keyBody := string(pem.EncodeToMemory(&pemBlock))

		fmt.Println(keyBody)
		fmt.Println("============================== PRIVATE KEY  私钥===================")
		return pk
	}
	return nil
}

func LoadPublicKey(pemPath string) *rsa.PublicKey {

	key, _ := ioutil.ReadFile(pemPath)
	block, _ := pem.Decode(key)
	if block == nil {
		return nil
	}

	certBody, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	publicKeyDer, err := x509.MarshalPKIXPublicKey(certBody.PublicKey)
	if err != nil {
		fmt.Print(err.Error())
		return nil
	}
	publickeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publickeyBlock))
	fmt.Println(publicKeyPem)
	fmt.Println("============================== PUBLIC KEY ===================")
	pb := certBody.PublicKey.(*rsa.PublicKey)
	return pb
}

// 签名
func SignSand(privateKey *rsa.PrivateKey, data string) (string, error) {

	h := crypto.SHA1.New()
	h.Write([]byte(data))

	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, h.Sum(nil))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sign), err
}

func SandVerification(data, signature []byte, publicKey *rsa.PublicKey) error {

	hash := crypto.SHA1
	if !hash.Available() {
		return fmt.Errorf("crypto: requested hash function (%s) is unavailable", hash.String())
	}

	h := hash.New()
	h.Write(data)

	return rsa.VerifyPKCS1v15(publicKey, hash, h.Sum(nil), signature)
}

//验签
func verification(data, signStr string, PublickKeyP *rsa.PublicKey) error {

	sign, err := base64.StdEncoding.DecodeString(strings.Replace(signStr, " ", "+", -1))
	if err != nil {
		return err
	}
	return SandVerification([]byte(data), sign, PublickKeyP)
}
