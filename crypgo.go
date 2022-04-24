/*
  Copyright (c) 2022-, Germano Rizzo <oss /AT/ germanorizzo /DOT/ it>

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

// Version 1.2.0

package crypgo

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/klauspost/compress/zstd"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const format byte = 1

const ivSize = chacha20poly1305.NonceSizeX
const keySize = chacha20poly1305.KeySize

const scryptSaltSize = 8
const scryptN = 1024
const scryptR = 8
const scryptP = 1

var base64Variant = base64.StdEncoding

// Sets a Base64 variant, for example base64.URLEncoding for
// URL_safe encoding.
func SetVariant(variant *base64.Encoding) {
	base64Variant = variant
}

func pwdToKey(salt []byte, password string) ([]byte, error) {
	dk, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, err
	}
	return dk, nil
}

func genBytes(size int) []byte {
	ret := make([]byte, size)
	_, _ = rand.Read(ret)
	return ret
}

// This function receives a password and a plain text (in string form) and produces a string
// with their encryption. Returns it, or an eventual error, and closes all related resources.
//
// More in detail:
//
// - generates a key derived from the password, using SCrypt;
//
// - converts the plain text to a byte array;
//
// - encrypts the data with the key using XChaCha20-Poly1305, with an authentication tag.
//
// No compression is performed.
//
// The output string is the output data, Base64-encoded. It contains:
//
// - an header with the format version and information on whether data were encrypted or not;
//
// - an array of random bytes, used as the Salt for SCrypt and IV for XChaCha;
//
// - encrypted data;
//
// - an authentication tag, part of the output of XChaCha20-Poly1305, used to verify the integrity when decrypting.
func Encrypt(password string, plainText string) (string, error) {
	return encryptBytes(password, []byte(plainText), 0)
}

// This function receives a password and a plain text (in string form), and a level for
// compression (from 1 to 19) and produces a string with their encryption, compressing the
// plaintext if possible. Returns it, or an eventual error, and closes all related resources.
//
// More in detail:
//
// - generates a key derived from the password, using SCrypt;
//
// - converts the plain text to a byte array;
//
// - compresses this array using ZStd and the given compression level;
//
//   - if the data aren't compressible, keeps the uncompressed data;
//
// - encrypts the data with the key using XChaCha20-Poly1305, with an authentication tag.
//
// The output string is the output data, Base64-encoded. It contains:
//
// - an header with the format version and information on whether data were encrypted or not;
//
// - an array of random bytes, used as the Salt for SCrypt and IV for XChaCha;
//
// - encrypted data;
//
// - an authentication tag, part of the output of XChaCha20-Poly1305, used to verify the integrity when decrypting.
func CompressAndEncrypt(password string, plainText string, zLevel int) (string, error) {
	if zLevel < 1 || zLevel > 19 {
		return "", errors.New("zLevel must be between 1 and 19")
	}
	return encryptBytes(password, []byte(plainText), zLevel)
}

// This function receives a password and a cypher text (as produced by one of the Encrypt* methods)
// and decodes the original plaintext (if the password is the one used for encryption).
//
// It will return it or an eventual error, and closes all related resources.
// XChaCha20-Poly1305's authentication tag is used to detect any decryption error. It also
// transparently decompress data, if needed.
func Decrypt(password string, base64CipherText string) (string, error) {
	b, err := DecryptBytes(password, base64CipherText)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// This function receives a password and a a byte array and produces a string
// with their encryption. Returns it, or an eventual error, and closes all related resources.
//
// More in detail:
//
// - generates a key derived from the password, using SCrypt;
//
// - encrypts the data with the key using XChaCha20-Poly1305, with an authentication tag.
//
// No compression is performed.
//
// The output string is the output data, Base64-encoded. It contains:
//
// - an header with the format version and information on whether data were encrypted or not;
//
// - an array of random bytes, used as the Salt for SCrypt and IV for XChaCha;
//
// - encrypted data;
//
// - an authentication tag, part of the output of XChaCha20-Poly1305, used to verify the integrity when decrypting.
func EncryptBytes(password string, plainText []byte) (string, error) {
	return encryptBytes(password, plainText, 0)
}

// This function receives a password, a byte array, and a level for
// compression (from 1 to 19) and produces a string with their encryption, compressing the
// byte array if possible. Returns it, or an eventual error, and closes all related resources.
//
// More in detail:
//
// - generates a key derived from the password, using SCrypt;
//
// - compresses the byte array using ZStd and the given compression level;
//
//   - if the data aren't compressible, keeps the uncompressed data;
//
// - encrypts the data with the key using XChaCha20-Poly1305, with an authentication tag.
//
// The output string is the output data, Base64-encoded. It contains:
//
// - an header with the format version and information on whether data were encrypted or not;
//
// - an array of random bytes, used as the Salt for SCrypt and IV for XChaCha;
//
// - encrypted data;
//
// - an authentication tag, part of the output of XChaCha20-Poly1305, used to verify the integrity when decrypting.
func CompressAndEncryptBytes(password string, plainText []byte, zLevel int) (string, error) {
	if zLevel < 1 || zLevel > 19 {
		return "", errors.New("zLevel must be between 1 and 19")
	}
	return encryptBytes(password, plainText, zLevel)
}

func zstdLvl2kpLvl(zstdLvl int) zstd.EncoderLevel {
	if zstdLvl < 3 {
		return zstd.SpeedFastest
	}
	if zstdLvl < 7 {
		return zstd.SpeedDefault
	}
	if zstdLvl < 11 {
		return zstd.SpeedBetterCompression
	}
	return zstd.SpeedBestCompression
}

func encryptBytes(password string, plainBytes []byte, zLevel int) (string, error) {
	header := []byte{format, 0}

	iv := genBytes(ivSize)
	salt := iv[:scryptSaltSize]

	key, err := pwdToKey(salt, password)
	if err != nil {
		return "", err
	}

	var zBytes []byte
	if zLevel > 0 {
		klauspostLevel := zstdLvl2kpLvl(zLevel)

		var encoder, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevel(klauspostLevel)))
		zBytes = encoder.EncodeAll(plainBytes, make([]byte, 0, len(plainBytes)))
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

	return base64Variant.EncodeToString(outBytes), nil
}

var decoder, _ = zstd.NewReader(nil)

// This function receives a password and a cypher text (as produced by one of the *EncryptBytes methods)
// and decodes the original plaintext (if the password is the one used for encryption).
//
// It will return it or an eventual error, and closes all related resources.
// XChaCha20-Poly1305's authentication tag is used to detect any decryption error. It also
// transparently decompress data, if needed.
func DecryptBytes(password string, base64CipherText string) ([]byte, error) {
	inBytes, err := base64Variant.DecodeString(base64CipherText)
	if err != nil {
		return make([]byte, 0), err
	}

	header := inBytes[:2]

	if header[0] != format {
		return make([]byte, 0), errors.New("unknown format")
	}

	iv := inBytes[2 : ivSize+2]
	salt := inBytes[2 : scryptSaltSize+2]
	cypherBytes := inBytes[2+ivSize:]

	key, err := pwdToKey(salt, password)
	if err != nil {
		return make([]byte, 0), err
	}

	c, err := chacha20poly1305.NewX(key)
	if err != nil {
		return make([]byte, 0), err
	}
	plainBytes, err := c.Open(nil, iv, cypherBytes, header)

	if header[1] == 1 {
		plainBytes, err = decoder.DecodeAll(plainBytes, nil)
		if err != nil {
			return make([]byte, 0), err
		}
	}

	if err != nil {
		return make([]byte, 0), err
	}

	return plainBytes, nil
}
