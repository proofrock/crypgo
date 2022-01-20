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

// Version 0.2.1

package crypgo

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/DataDog/zstd"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

var format byte = 1

const ivSize = chacha20poly1305.NonceSizeX
const keySize = chacha20poly1305.KeySize

const scryptSaltSize = 8
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

func genBytes(size int) []byte {
	ret := make([]byte, size)
	rand.Read(ret)
	return ret
}

func Encrypt(password string, plainText string) (string, error) {
	return encrypt(password, plainText, 0)
}

func CompressAndEncrypt(password string, plainText string, zLevel int) (string, error) {
	if zLevel < 1 || zLevel > 19 {
		return "", errors.New("zLevel must be between 1 and 19")
	}
	return encrypt(password, plainText, zLevel)
}

func encrypt(password string, plainText string, zLevel int) (string, error) {
	header := []byte{format, 0}

	iv := genBytes(ivSize)
	salt := iv[:scryptSaltSize]

	key, err := pwdToKey(salt, password)
	if err != nil {
		return "", err
	}

	plainBytes := []byte(plainText)

	var zBytes []byte
	if zLevel > 0 {
		zBytes, err = zstd.CompressLevel(nil, plainBytes, 19)
		if err != nil {
			return "", err
		}
		if len(zBytes) < len(plainBytes) {
			header[1] = 1
		} else {
			zBytes = plainBytes
		}
	} else {
		zBytes = plainBytes
	}

	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	cypherBytes := c.Seal(nil, iv, zBytes, header)

	outBytes := append(header, append(iv, cypherBytes...)...)

	return base64.StdEncoding.EncodeToString(outBytes), nil
}

func Decrypt(password string, base64CipherText string) (string, error) {
	inBytes, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		return "", err
	}

	header := inBytes[:2]

	if header[0] != format {
		return "", errors.New("unknown format")
	}

	iv := inBytes[2 : ivSize+2]
	salt := inBytes[2 : scryptSaltSize+2]
	cypherBytes := inBytes[2+ivSize:]

	key, err := pwdToKey(salt, password)
	if err != nil {
		return "", err
	}

	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	plainBytes, err := c.Open(nil, iv, cypherBytes, header)

	if header[1] == 1 {
		plainBytes, err = zstd.Decompress(nil, plainBytes)
		if err != nil {
			return "", err
		}
	}

	if err != nil {
		return "", err
	}

	return string(plainBytes), nil
}
