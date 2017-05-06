package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/howeyc/gopass"
	"github.com/starius/encio"
)

func NewAEAD(key []byte) (cipher.AEAD, error) {
	h := sha256.Sum256(key)
	block, err := aes.NewCipher(h[:])
	if err != nil {
		return nil, fmt.Errorf("Failed to make AES: %s", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Failed to make AEAD: %s", err)
	}
	return aead, nil
}

var (
	store = flag.String("store", "", "Encrypted store file")
	begin = flag.Int64("begin", 0, "First byte index (0-based)")
	end   = flag.Int64("end", 0, "Index of the byte after last (0-based), -1 for end")
	out   = flag.String("out", "", "Output file")
)

func main() {
	flag.Parse()
	if *store == "" || *out == "" {
		flag.PrintDefaults()
		log.Fatal("Provide -store and -out")
	}
	backend, err := os.OpenFile(*store, os.O_RDONLY, 0600)
	if err != nil {
		log.Fatalf("Failed to open store file: %s", err)
	}
	defer backend.Close()
	fmt.Printf("Enter password for %s: ", *store)
	password, err := gopass.GetPasswdMasked()
	if err != nil {
		log.Fatalf("Failed to input password: %s", err)
	}
	aead, err := NewAEAD(password)
	if err != nil {
		log.Fatalf("Failed to make AEAD: %s", err)
	}
	frontend := encio.NewAppender(aead, backend, 4096)
	if *end == -1 {
		if stat, err := frontend.Stat(); err != nil {
			log.Fatalf("Failed to stat frontend: %s", err)
		} else {
			*end = stat.Size()
		}
	}
	if *begin < 0 || *end < *begin {
		log.Fatalf("Incorrect range [%d,%d)", *begin, *end)
	}
	buf := make([]byte, *end-*begin)
	if _, err := frontend.ReadAt(buf, *begin); err != nil {
		log.Fatalf("Failed to read: %s", err)
	}
	if err := ioutil.WriteFile(*out, buf, 0600); err != nil {
		log.Fatalf("Failed to write: %s", err)
	}
}
