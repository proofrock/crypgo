package crypgo

import (
	"fmt"
	"io"
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
