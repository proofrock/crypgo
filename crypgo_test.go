package crypgo

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"testing"
)

func Test(t *testing.T) {
	password := "hello"
	plaintext := "world"

	cyphertext, err := Encrypt(password, plaintext)
	if err != nil {
		t.Errorf("error in encoding: %v", err)
		return
	}

	plaintext2, err := Decrypt(password, cyphertext)
	if err != nil {
		t.Errorf("error in decoding: %v", err)
		return
	}

	if plaintext != plaintext2 {
		t.Error("error in comparing results")
	}
}

func TestUnicode(t *testing.T) {
	password := "你好"
	plaintext := "世界"

	cyphertext, err := Encrypt(password, plaintext)
	if err != nil {
		t.Errorf("error in encoding: %v", err)
		return
	}

	plaintext2, err := Decrypt(password, cyphertext)
	if err != nil {
		t.Errorf("error in decoding: %v", err)
		return
	}

	if plaintext != plaintext2 {
		t.Error("error in comparing results")
	}
}

func load(url string) string {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	ret, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(ret)
}

func TestLongString(t *testing.T) {
	prufrock := load("https://www.gutenberg.org/cache/epub/1459/pg1459.txt")
	password := "1234567890"
	cyphertext, err := CompressAndEncrypt(password, prufrock, 19)
	if err != nil {
		t.Errorf("error in encoding: %v", err)
		return
	}

	fmt.Printf("%d -> %d\n", len(prufrock), len(cyphertext))

	plaintext2, err := Decrypt(password, cyphertext)
	if err != nil {
		t.Errorf("error in decoding: %v", err)
		return
	}

	if len(cyphertext) > len(prufrock) {
		t.Error("length should be decreasing")
		return
	}

	if prufrock != plaintext2 {
		t.Error("error in comparing results")
	}
}

func TestBytes(t *testing.T) {
	prufrock := make([]byte, 5000)
	_, err := rand.Read(prufrock)
	if err != nil {
		t.Errorf("error in collecting rnd: %v", err)
		return
	}

	password := "1234567890"
	cyphertext, err := EncryptBytes(password, prufrock)
	if err != nil {
		t.Errorf("error in encoding: %v", err)
		return
	}

	plaintext2, err := DecryptBytes(password, cyphertext)
	if err != nil {
		t.Errorf("error in decoding: %v", err)
		return
	}

	if !bytes.Equal(prufrock, plaintext2) {
		t.Error("error in comparing results")
	}
}

func TestAltBase64(t *testing.T) {
	SetVariant(base64.URLEncoding)
	defer SetVariant(base64.StdEncoding)

	prufrock := load("https://www.gutenberg.org/cache/epub/1459/pg1459.txt")
	password := "1234567890"
	cyphertext, err := CompressAndEncrypt(password, prufrock, 19)
	if err != nil {
		t.Errorf("error in encoding: %v", err)
		return
	}

	plaintext2, err := Decrypt(password, cyphertext)
	if err != nil {
		t.Errorf("error in decoding: %v", err)
		return
	}

	if len(cyphertext) > len(prufrock) {
		t.Error("length should be decreasing")
		return
	}

	if prufrock != plaintext2 {
		t.Error("error in comparing results")
	}
}

func TestCompression(t *testing.T) {
	prufrock := make([]byte, 5000)
	_, err := rand.Read(prufrock)
	if err != nil {
		t.Errorf("error in collecting rnd: %v", err)
		return
	}

	for lvl := 1; lvl <= 19; lvl++ {
		password := "1234567890"
		cyphertext, err := CompressAndEncryptBytes(password, prufrock, lvl)
		if err != nil {
			t.Errorf("error in encoding: %v", err)
			return
		}

		plaintext2, err := DecryptBytes(password, cyphertext)
		if err != nil {
			t.Errorf("error in decoding: %v", err)
			return
		}

		if !bytes.Equal(prufrock, plaintext2) {
			t.Error("error in comparing results")
		}
	}
}

// test just decompression, to test regressions when switching libs
func TestFixedDecompression(t *testing.T) {
	str := "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	cyph := "AQGz4+KJeOgLKeMRESeZcRiAB4RGO7p4gN3Bf9zVkKqZUsLZM69jaU3EAN7q+jnCpHhmYCnD1N3I4A=="
	password := "1234567890"

	plaintext2, err := Decrypt(password, cyph)
	if err != nil {
		t.Errorf("error in decoding: %v", err)
		return
	}

	if str != plaintext2 {
		t.Error("error in comparing results")
	}
}
