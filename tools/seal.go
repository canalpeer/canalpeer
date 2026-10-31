// Command seal encrypts stdin to stdout with AES-256-GCM: "CPM1", a 12-byte
// nonce, then the ciphertext. The key is MIRROR_KEY, 64 hex characters.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"os"
)

func main() {
	key, err := hex.DecodeString(os.Getenv("MIRROR_KEY"))
	if err != nil || len(key) != 32 {
		log.Fatal("MIRROR_KEY must be 64 hex characters")
	}
	plain, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	os.Stdout.Write(append(append([]byte("CPM1"), nonce...), gcm.Seal(nil, nonce, plain, nil)...))
}
