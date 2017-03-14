# encio
Crypto layer library for IO in Go

The library takes a real file handle and returns another file-like
object, all operations on that are translated to the first file, but
all the data is encrypted and authenticated in between.
