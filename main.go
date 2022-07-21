package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
)

const key = "use-openssl-rand--base64--256key"

// Simplify code error ck
func ckErr(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}

func main() {

	encText, err := encrypt([]byte("Hello from GoLang"), []byte(key))
	ckErr(err)

	fmt.Println("GoEnc:", hex.EncodeToString(encText))

	//decText, err := decrypt(encText, []byte(key))
	//ckErr(err)
	//fmt.Println(string(decText))

	// Dart decrypt
	dartCipher, err := hex.DecodeString("7237c8f8982d16545d29099ec45773ef736472dc2697f98541a540286790a414d2c4d1fdcac2639b219261")
	ckErr(err)

	dartDecText, err := decrypt(dartCipher, []byte(key))
	ckErr(err)

	fmt.Println("GoDec:", string(dartDecText))
}

func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	ckErr(err)

	gcm, err := cipher.NewGCM(c)
	ckErr(err)

	// random nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	ckErr(err)

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decriptare text
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	secretKey, err := aes.NewCipher(key)
	ckErr(err)

	algo, err := cipher.NewGCM(secretKey)
	ckErr(err)

	nonceSize := algo.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	/*
		// MacSize is just for info, GoLang is smart enough to figure out it's mac size...
		macSize := 16
		mac := ciphertext[(len(ciphertext) - macSize):]
		fmt.Println("Mac:", len(mac), mac)
	*/

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	fmt.Println("Nonce:", len(nonce), nonce)
	fmt.Println("CipherText:", len(ciphertext), ciphertext)

	return algo.Open(nil, nonce, ciphertext, nil)
}
