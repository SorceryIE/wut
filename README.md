# wut
Wut is a cli tool designed to try figure out what an arbitrary string of data is by trying different decoding and decompression methods on it and some basic analysis.
It works recursively as well so no need to decode the base64 etc before passing the data to wut.

## Installation
```sh
git clone git@github.com:SorceryIE/wut.git
cd wut
python -m pip install .
```

## Usage
```sh
echo "ABCDEF" | wut
wut "ABCDEF"
wut file.bin
```

## Supported Compressions
- gzip
- zlib
- bzip2
- lzma
- brotli
- deflate
- deflate stream
- zstd/zstandard
- lz4
- lzw
- lzfse
- lzvn
- snappy
- quicklz
- lzo (LZO1, LZO1A, LZO1B, LZO1C, LZO1F, LZO1X, LZO1Y, LZO1Z, LZO2A)

## Other detections
- base64 (including base64url)
- zero padding
- pkcs7 padding
- shannon entropy
- mime detection
- encoding detection

# Todo
## Compressions to add
- lz4 streams (lz4.stream in python-lz4 is experimental and doesnt work)
- lzip
- Deflate64
- lzs
- lzss
- LZRW1-A
- LZV
- LZO2B
- blosc2 (mentioned in cramjam lib)
- lzham (tried pylzham but it just hangs when given bad data)

## Other
- Add more tests
- Improve detection for the compressions when headers are stripped

## Other useful links
- [signsrch](https://aluigi.altervista.org/mytoolz.htm)
