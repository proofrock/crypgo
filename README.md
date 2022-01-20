# crypgo

A simple, very simple, dead simple Go library that encrypts/decrypts/hashes strings to strings.

## Import

```
go get github.com/proofrock/crypgo
```

## Usage

Given a `password` and a `plaintext`, we want to encrypt and decrypt them:

```go
password := "hello"
	plaintext := "world"
	
	cyphertext, err := crypgo.Encode(password, plaintext)
	if err != nil {
		// ...
	}

	plaintext2, err := crypgo.Decode(password, cyphertext)
	if err != nil {
		// ...
	}

	assert(plaintext == plaintext2)
```

## Notes

`cyphertext` will be base64, and include a checksum, the various salts/IVs, and the encrypted plaintext, of course. Expect it to be longer than plaintext.
