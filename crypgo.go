/*
  Copyright (c) 2022-, Germano Rizzo <oss@germanorizzo.it>

  Permission to use, copy, modify, and/or distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

package crypgo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/scrypt"
)

const hashSize = 32

const saltSize = 8

const ivSize = 16

const keySize = 32

const scryptN = 1024

const scryptR = 8

const scryptP = 1

func pwdToKey(salt []byte, password string) ([]byte, error) {
	dk, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

func encDec(iv []byte, key []byte, input []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(c, iv)
	out := make([]byte, len(input))
	ctr.XORKeyStream(out, input)
	return out, nil
}

func Hash(input []byte) []byte {
	hash := sha256.Sum256(input)
	return hash[:]
}

func genBytes(size int) []byte {
	ret := make([]byte, size)
	rand.Read(ret)
	return ret
}

func Decode(password string, base64CipherText string) (string, error) {
	inBytes, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		return "", err
	}

	salt := inBytes[0:saltSize]
	iv := inBytes[saltSize : saltSize+ivSize]
	loadedHash := inBytes[saltSize+ivSize : saltSize+ivSize+hashSize]
	cipherBytes := inBytes[saltSize+ivSize+hashSize:]

	key, err := pwdToKey(salt, password)
	if err != nil {
		return "", err
	}

	plainBytes, err := encDec(iv, key, cipherBytes)
	if err != nil {
		return "", err
	}

	myHash := Hash(plainBytes)

	if !bytes.Equal(loadedHash, myHash) {
		return "", errors.New("wrong password or corrupted data")
	}

	return string(plainBytes), nil
}

func Encode(password string, plainText string) (string, error) {
	salt := genBytes(saltSize)
	iv := genBytes(ivSize)
	key, err := pwdToKey(salt, password)
	if err != nil {
		return "", err
	}

	plainBytes := []byte(plainText)
	cipherBytes, err := encDec(iv, key, plainBytes)
	if err != nil {
		return "", err
	}

	myHash := Hash(plainBytes)
	outBytes := append(salt, append(iv, append(myHash, cipherBytes...)...)...)

	return base64.StdEncoding.EncodeToString(outBytes), nil
}
