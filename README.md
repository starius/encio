# encio

[![Travis build][travis-badge]][travis-page]
[![AppVeyor build][appveyor-badge]][appveyor-page]
[![License][license]](LICENSE)

Crypto layer library for IO in Go

The library takes a real file handle and returns another file-like
object, all operations on that are translated to the first file, but
all the data is encrypted and authenticated in between.

[travis-page]: https://travis-ci.org/starius/encio
[travis-badge]: https://travis-ci.org/starius/encio.png
[appveyor-page]: https://ci.appveyor.com/project/starius/encio
[appveyor-badge]: https://ci.appveyor.com/api/projects/status/q9osdcrxl29xvymp
[license]: https://img.shields.io/badge/License-MIT-brightgreen.png
