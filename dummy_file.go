package encio

import (
	"fmt"
	"os"
)

// dummyFile is in-memory implementation of StoreFile.
type dummyFile struct {
	buffer [1024 * 1024]byte
	size   int64
}

func (d *dummyFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("reading with negative offset")
	}
	end := off + int64(len(p))
	if end > d.size {
		return 0, fmt.Errorf("reading out of file data")
	}
	copy(p, d.buffer[off:end])
	return len(p), nil
}

func (d *dummyFile) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("writing with negative offset")
	}
	end := off + int64(len(p))
	if end > int64(len(d.buffer)) {
		return 0, fmt.Errorf("writing too large file")
	}
	copy(d.buffer[off:end], p)
	if d.size < end {
		d.size = end
	}
	return len(p), nil
}

func (d *dummyFile) Stat() (os.FileInfo, error) {
	return fileInfo{
		size: d.size,
	}, nil
}

func (d *dummyFile) Truncate(size int64) error {
	if size < 0 {
		return fmt.Errorf("truncating with negative size")
	}
	if size > int64(len(d.buffer)) {
		return fmt.Errorf("truncating to too large size")
	}
	d.size = size
	return nil
}
