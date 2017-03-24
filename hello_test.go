package encio

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func ExampleHello() {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		log.Fatalf("Failed to make AES: %s", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Failed to make AEAD: %s", err)
	}
	backend, err := ioutil.TempFile("", "test-encio-hello-")
	if err != nil {
		log.Fatalf("Failed to create temp file: %s.", err)
	}
	defer os.Remove(backend.Name())
	defer backend.Close()
	if err != nil {
		log.Fatalf("Failed to open backend: %s", err)
	}
	frontend := NewAppender(aead, backend, 4096)
	_, err = frontend.WriteAt([]byte("Hello"), 0)
	if err != nil {
		log.Fatalf("Failed to write: %s", err)
	}
	_, err = frontend.WriteAt([]byte(" world"), 5)
	if err != nil {
		log.Fatalf("Failed to write: %s", err)
	}
	b := make([]byte, 11)
	_, err = frontend.ReadAt(b, 0)
	if err != nil {
		log.Fatalf("Failed to write: %s", err)
	}
	fmt.Println(string(b))
	// Output: Hello world
}
