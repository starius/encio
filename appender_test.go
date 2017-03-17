package encio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"testing"
)

func setupDummies() (aead cipher.AEAD, backend, frontend StoreFile) {
	backend = &dummyFile{}
	aead = dummyAEAD{
		overheadSize: 32,
		nonceSize:    16,
	}
	frontend = NewAppender(aead, backend)
	return aead, backend, frontend
}

func genPlaintext(size int) []byte {
	p := make([]byte, size)
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	ctr := cipher.NewCTR(block, make([]byte, block.BlockSize()))
	ctr.XORKeyStream(p, p)
	return p
}

func TestStat(t *testing.T) {
	_, _, frontend := setupDummies()
	stat, err := frontend.Stat()
	if err != nil {
		t.Errorf("Failed to make frontend.Stat: %s", err)
	}
	if stat.Size() != 0 {
		t.Errorf("frontend.Stat().Size() != 0")
	}
	if _, err := frontend.WriteAt(make([]byte, 10000), 0); err != nil {
		t.Errorf("Failed to write 10000 zeros: %s", err)
	}
	stat, err = frontend.Stat()
	if err != nil {
		t.Errorf("Failed to make frontend.Stat (2): %s", err)
	}
	if stat.Size() != 10000 {
		t.Errorf("frontend.Stat().Size() != 10000")
	}
}

func TestManyWrites(t *testing.T) {
	_, _, frontend := setupDummies()
	plain := genPlaintext(100000)
	r := rand.New(rand.NewSource(0))
	input := plain
	for len(input) > 0 {
		n := 10000
		if n > len(input) {
			n = len(input)
		}
		l := r.Intn(n) + 1
		off := int64(len(plain) - len(input))
		if _, err := frontend.WriteAt(input[:l], off); err != nil {
			t.Errorf("Failed to write: %s", err)
		}
		input = input[l:]
	}
	checked := make([]byte, 100000)
	if _, err := frontend.ReadAt(checked, 0); err != nil {
		t.Errorf("Failed to read: %s", err)
	}
	if !bytes.Equal(checked, plain) {
		t.Errorf("checked != plain")
	}
}

func TestManyReads(t *testing.T) {
	_, _, frontend := setupDummies()
	plain := genPlaintext(100000)
	if _, err := frontend.WriteAt(plain, 0); err != nil {
		t.Fatalf("Failed to write: %s", err)
	}
	r := rand.New(rand.NewSource(0))
	checked0 := make([]byte, 100000)
	for i := 0; i < 10000; i++ {
		begin := r.Intn(100000)
		end := begin + r.Intn(100000-begin)
		l := end - begin
		checked := checked0[:l]
		if _, err := frontend.ReadAt(checked, int64(begin)); err != nil {
			t.Errorf("Failed to read %d-%d: %s", begin, end, err)
			continue
		}
		if !bytes.Equal(checked, plain[begin:end]) {
			t.Errorf("checked != plain[begin:end]")
		}
	}
}
