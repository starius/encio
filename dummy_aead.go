package encio

import (
	"bytes"
	"fmt"
)

// DummyAEAD is noop implementation of cipher.AEAD used in tests.
// Ciphertext = overhead + plaintext;
// overhead is nonce padded by zeros.
type DummyAEAD struct {
	nonceSize, overheadSize int
}

func (d DummyAEAD) NonceSize() int {
	return d.nonceSize
}

func (d DummyAEAD) Overhead() int {
	return d.overheadSize
}

func (d DummyAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if additionalData != nil {
		panic("additionalData is not supported")
	}
	if d.overheadSize < d.nonceSize {
		panic("d.overheadSize < d.nonce")
	}
	if len(nonce) != d.nonceSize {
		panic("len(nonce) != d.nonce")
	}
	o := make([]byte, d.overheadSize)
	copy(o, nonce)
	dst = append(dst, o...)
	dst = append(dst, plaintext...)
	return dst
}

func (d DummyAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if additionalData != nil {
		panic("additionalData is not supported")
	}
	if d.overheadSize < d.nonceSize {
		panic("d.overheadSize < d.nonce")
	}
	if len(nonce) != d.nonceSize {
		panic("len(nonce) != d.nonce")
	}
	if !bytes.Equal(nonce, ciphertext[:d.nonceSize]) {
		return nil, fmt.Errorf("ciphertext does not start with nonce")
	}
	dst = append(dst, ciphertext[d.overheadSize:]...)
	return dst, nil
}
