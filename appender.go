package encio

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const (
	usedLen = 2
)

// StoreFile is abstraction of a file with random access.
// It is implemented by os.File and it is used by
// https://github.com/steveyen/gkvlite
type StoreFile interface {
	io.ReaderAt
	io.WriterAt
	Stat() (os.FileInfo, error)
	Truncate(size int64) error
}

// Frontend is an encrypted implementation of StoreFile,
// which supports only appending to the end.
// Content of a virtual plaintext file is mapped by Frontend to
// an encrypted file. Ciphertext is splitted to blocks of size
// 4096 bytes (TODO: make this an argument of NewAppender).
// Plaintext block size is less than ciphertext block size by
// aead.Overhead(). Plaintext block is encrypted and authenticated
// using aead and written to the corresponding ciphertext block.
// Nonce of aead is a one-to-one function of a tuple of the block
// index and of its size. Only last block and change and only by
// growing it size, so a nonce value is never reused.
// Frontend provides concurrent access of multiple readers
// xor a signle writer.
type Frontend struct {
	aead    cipher.AEAD
	backend StoreFile

	plainBlockSize, cipherBlockSize, overhead int64

	m sync.RWMutex
}

// NewAppender creates Frontend from aead and ciphertext file.
func NewAppender(aead cipher.AEAD, backend StoreFile) *Frontend {
	cipherBlockSize := 4096
	plainBlockSize := cipherBlockSize - aead.Overhead()
	return &Frontend{
		aead:            aead,
		backend:         backend,
		cipherBlockSize: int64(cipherBlockSize),
		plainBlockSize:  int64(plainBlockSize),
		overhead:        int64(aead.Overhead()),
	}
}

func makeNonce(nonceSize, lenP int, block int64) []byte {
	nonce := make([]byte, nonceSize)
	// usedSize is the number of bytes in nonce used to store the size
	// of plain text. It is needed because last bucket may have
	// any size.
	used := nonce[:usedLen]
	blockNo := nonce[usedLen:]
	if len(blockNo) < 8 {
		panic("bad len(blockNo)")
	}
	binary.LittleEndian.PutUint16(used, uint16(lenP))
	binary.LittleEndian.PutUint64(blockNo, uint64(block))
	return nonce
}

func decrypt(aead cipher.AEAD, c, p []byte, block int64) error {
	if len(c) != len(p)+aead.Overhead() {
		panic("len(c) != len(p) + aead.Overhead()")
	}
	nonce := makeNonce(aead.NonceSize(), len(p), block)
	p2, err := aead.Open(p[:0], nonce, c, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %s", err)
	} else if len(p2) != len(p) {
		return fmt.Errorf("open: want %d bytes, got %d", len(p), len(p2))
	}
	return nil
}

func encrypt(aead cipher.AEAD, c, p []byte, block int64) error {
	if len(c) != len(p)+aead.Overhead() {
		panic("len(c) != len(p) + aead.Overhead()")
	}
	nonce := makeNonce(aead.NonceSize(), len(p), block)
	c2 := aead.Seal(c[:0], nonce, p, nil)
	if len(c2) != len(c) {
		return fmt.Errorf("seal: want %d bytes, got %d", len(c), len(c2))
	}
	return nil
}

func blocksRange(lenP int, off, plainBlockSize int64) (int64, int64) {
	lastByte := off + int64(lenP) - 1
	firstBlock := off / plainBlockSize
	lastBlock := lastByte / plainBlockSize
	return firstBlock, lastBlock
}

func getBlock(buffer []byte, i, blockSize int64) []byte {
	begin := i * blockSize
	end := begin + blockSize
	if end > int64(len(buffer)) {
		end = int64(len(buffer))
	}
	return buffer[begin:end]
}

// ReadAt reads len(b) bytes from the file starting at byte offset off.
func (f *Frontend) ReadAt(p []byte, off int64) (int, error) {
	f.m.RLock()
	defer f.m.RUnlock()
	return f.readAt(p, off)
}

func (f *Frontend) readAt(p0 []byte, off int64) (int, error) {
	if len(p0) == 0 {
		return 0, nil
	}
	plainSize, cipherSize, _, err := f.getSizes()
	if err != nil {
		return 0, fmt.Errorf("Failed to get size: %s", err)
	} else if off+int64(len(p0)) > plainSize {
		return 0, fmt.Errorf("Reading out-of-file data")
	}
	firstBlock, lastBlock := blocksRange(len(p0), off, f.plainBlockSize)
	headLen := off % f.plainBlockSize
	plainEnd := (lastBlock + 1) * f.plainBlockSize
	if plainEnd > plainSize {
		plainEnd = plainSize
	}
	psize := plainEnd - off + headLen
	head := make([]byte, headLen, psize)
	tail := make([]byte, psize-headLen-int64(len(p0)))
	p := append(head, p0...)
	p = append(p, tail...)
	cipherBegin := firstBlock * f.cipherBlockSize
	cipherEnd := (lastBlock + 1) * f.cipherBlockSize
	if cipherEnd > cipherSize {
		cipherEnd = cipherSize
	}
	c := make([]byte, cipherEnd-cipherBegin)
	n0, err := f.backend.ReadAt(c, cipherBegin)
	if err != nil {
		return 0, fmt.Errorf("backend: failed to read: %s", err)
	} else if n0 != len(c) {
		return 0, fmt.Errorf("want to read %d bytes, got %d", len(c), n0)
	}
	for block := firstBlock; block <= lastBlock; block++ {
		cblock := getBlock(c, block-firstBlock, f.cipherBlockSize)
		pblock := getBlock(p, block-firstBlock, f.plainBlockSize)
		err := decrypt(f.aead, cblock, pblock, block)
		if err != nil {
			return 0, err
		}
	}
	desired := p[len(head) : len(p)-len(tail)]
	if len(desired) != len(p0) {
		panic("len(desired) != len(p0)")
	}
	copy(p0, desired)
	return len(p0), nil
}

// WriteAt writes len(b) bytes to the File starting at byte offset off.
func (f *Frontend) WriteAt(p []byte, off int64) (int, error) {
	f.m.Lock()
	defer f.m.Unlock()
	return f.writeAt(p, off)
}

func (f *Frontend) writeAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	origN := len(p)
	plainSize, _, _, err := f.getSizes()
	if err != nil {
		return 0, fmt.Errorf("failed to get size: %s", err)
	} else if off < plainSize {
		return 0, fmt.Errorf("attempt to overwrite: %d < %d", off, plainSize)
	} else if off != plainSize {
		return 0, fmt.Errorf("gaps are not allowed")
	}
	plainShift := off % f.plainBlockSize
	if plainShift != 0 {
		tail := make([]byte, plainShift, plainShift+int64(len(p)))
		n, err := f.readAt(tail, off-plainShift)
		if err != nil {
			return 0, fmt.Errorf("failed to read tail: %s", err)
		} else if n != len(tail) {
			return 0, fmt.Errorf("want to read %d bytes, got %d", len(tail), n)
		}
		p = append(tail, p...)
		off -= plainShift
	}
	firstBlock, lastBlock := blocksRange(len(p), off, f.plainBlockSize)
	lastP := int64(len(p)) % f.plainBlockSize
	if lastP == 0 {
		lastP = f.plainBlockSize
	}
	lastC := lastP + f.overhead
	cipherBegin := firstBlock * f.cipherBlockSize
	cipherEnd := lastBlock*f.cipherBlockSize + lastC
	c := make([]byte, cipherEnd-cipherBegin)
	n := 0
	for block := firstBlock; block <= lastBlock; block++ {
		cblock := getBlock(c, block-firstBlock, f.cipherBlockSize)
		pblock := getBlock(p, block-firstBlock, f.plainBlockSize)
		err := encrypt(f.aead, cblock, pblock, block)
		if err != nil {
			return n, err
		}
		n += len(pblock)
	}
	if n != len(p) {
		panic("n != len(p)")
	}
	n0, err := f.backend.WriteAt(c, cipherBegin)
	if err != nil {
		return 0, fmt.Errorf("backend: failed to write: %s", err)
	} else if n0 != len(c) {
		return 0, fmt.Errorf("want to write %d bytes, got %d", len(c), n0)
	}
	return origN, nil
}

type fileInfo struct {
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (f fileInfo) Name() string {
	return "file"
}

func (f fileInfo) Size() int64 {
	return f.size
}

func (f fileInfo) Mode() os.FileMode {
	return f.mode
}

func (f fileInfo) ModTime() time.Time {
	return f.modTime
}

func (f fileInfo) IsDir() bool {
	return false
}

func (f fileInfo) Sys() interface{} {
	return nil
}

// Stat returns the FileInfo structure describing file.
func (f *Frontend) Stat() (os.FileInfo, error) {
	p, _, stat, err := f.getSizes()
	if err != nil {
		return nil, fmt.Errorf("Failed to get size: %s", err)
	}
	return fileInfo{
		size:    p,
		mode:    stat.Mode(),
		modTime: stat.ModTime(),
	}, nil
}

func (f *Frontend) getSizes() (p, c int64, stat os.FileInfo, err error) {
	// TODO: cache this value.
	bStat, err := f.backend.Stat()
	if err != nil {
		return 0, 0, bStat, fmt.Errorf("Failed to stat backend: %s", err)
	}
	cipherLength := bStat.Size()
	if cipherLength == 0 {
		return 0, 0, bStat, nil
	}
	fullBlocks := cipherLength / f.cipherBlockSize
	var lastInPlain int64
	lastInCipher := cipherLength - fullBlocks*f.cipherBlockSize
	if lastInCipher > 0 {
		lastInPlain = lastInCipher - f.overhead
	}
	p = fullBlocks*f.plainBlockSize + lastInPlain
	return p, cipherLength, bStat, nil
}

// Truncate changes the size of the file.
// Only grow operation is supported.
func (f *Frontend) Truncate(size int64) error {
	p, _, _, err := f.getSizes()
	if err != nil {
		return fmt.Errorf("Failed to get plain size: %s", err)
	}
	if size < p {
		return fmt.Errorf("Can't shrink the file")
	}
	if size > p {
		zeros := make([]byte, size-p)
		n, err := f.WriteAt(zeros, p)
		if err != nil {
			return fmt.Errorf("failed to write zeros: %s", err)
		}
		if n != len(zeros) {
			return fmt.Errorf(
				"Want to write %d bytes, got %d",
				len(zeros),
				n,
			)
		}
	}
	return nil
}
