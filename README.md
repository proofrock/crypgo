# crypgo

A dead simple Go library that encrypts, decrypts, and optionally compresses strings to strings.

Algorithms used:

- [Scrypt](https://en.wikipedia.org/wiki/Scrypt) to generate keys from passwords (N=1024, R=8, P=1);
- [XChaCha20Poly1305](https://www.cryptopp.com/wiki/XChaCha20Poly1305) to encrypt and ensure integrity ([AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption));
- [ZStd](https://en.wikipedia.org/wiki/Zstandard) to compress;
- [Base64](https://en.wikipedia.org/wiki/Base64) to encode bytes into string.

Compression is applied only if it reduces the size of the message.

## Import

```
go get github.com/proofrock/crypgo
```

## Usage

Given a `password` and a `plaintext`, we want to encrypt and decrypt them:

```go
password := "hello"
plaintext := "world"
	
cyphertext, err := crypgo.Encrypt(password, plaintext)
// or cyphertext, err := crypgo.CompressAndEncrypt(password, plaintext, 19)
if err != nil {
	// ...
}

plaintext2, err := crypgo.Decrypt(password, cyphertext)
if err != nil {
	// ...
}

assert(plaintext == plaintext2)
```
The third argument for `CompressAndEncrypt` is the compression level for zstd, values are 1 to 19 (inclusive).

## Notes

`cyphertext` will be Base64-encoded, and includes a checksum, the random bytes for the salt and IV (the same random bytes are used for Scrypt's salt and for XChaCha's nonce), and the encrypted/compressed plaintext, of course. Expect it to be longer than the plaintext, if compression is not applied.
