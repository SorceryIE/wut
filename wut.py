#!/usr/bin/python3
import argparse
import os
import math
import chardet
import base64
import magic
import gzip
import bz2
import zlib
import lzma
import brotli
import zstandard as zstd
import lz4.frame
import lz4.block
import snappy
import io
import lzo
import quicklz
import liblzfse
import ncompress
import lzallright
import sys

def shannon_entropy(data):
	# 256 different possible values
	possible = dict(((chr(x), 0) for x in range(0, 256)))

	for byte in data:
		possible[chr(byte)] +=1

	data_len = len(data)
	entropy = 0.0

	# compute
	for i in possible:
		if possible[i] == 0:
			continue

		p = float(possible[i] / data_len)
		entropy -= p * math.log(p, 2)
	return entropy

def is_b64(data):
	data = data.strip()
	if len(data) % 4 != 0:
		# I think some forms of b64 opt to not add the padding
		# might deal with that edge case later
		return False
	characters_used = set(data)
	allowed_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-") # - and _ are for urlsafe b64
	if not characters_used.issubset(allowed_chars):
		return False
	return True # this just means it can be decoded as base64, doesnt mean it is b64

def is_gzip(data):
	try:
		gzip.decompress(data)
		return True
	except (gzip.BadGzipFile, ValueError):
		pass
	return False

def is_zlib(data):
	try:
		zlib.decompress(data)
		return True
	except (zlib.error):
		pass
	return False

def is_bz2(data):
	try:
		bz2.decompress(data)
		return True
	except (OSError):
		pass
	return False

def is_lzma(data):
	try:
		x = lzma.decompress(data)
		if len(x) > 0:
			return True
	except (lzma.LZMAError):
		pass
	return False

def is_brotli(data):
	try:
		brotli.decompress(data)
		return True
	except (brotli.error):
		pass
	return False

def is_deflate(data):
	# False positive avoidance
	if len(data)<10:
		return False
	for val in [b'x\x01', b'x\x9c', b'x\xda']:
		try:
			zlib.decompressobj().decompress(val + data)
			return val
		except (zlib.error):
			pass
	return False

def is_deflatestream(data):
	# False positive avoidance
	if len(data)<10:
		return False
	#deflate streams end with a 4 byte adler32 checksum
	for val in [b'x\x01', b'x\x9c', b'x\xda']:
		try:
			zlib.decompressobj().decompress(val + data[2:-4])
			return val
		except (zlib.error):
			pass
	return False

def is_lz4(data):
	try:
		lz4.frame.decompress(data)
		return True
	except (RuntimeError):
		try:
			lz4.block.decompress(data, uncompressed_size=1000)
			return True
		except:
			return False

def unlz4(data):
	try:
		return lz4.frame.decompress(data)
	except (RuntimeError):
		return lz4.block.decompress(data, uncompressed_size=1000)

def is_zstd(data):
	try:
		zstd.decompress(data)
		return True
	except (zstd.ZstdError):
		# try with a stream
		try:
			zstd_dcmp = zstd.ZstdDecompressor()
			stream_reader = zstd_dcmp.stream_reader(data)
			stream_reader.read()
			stream_reader.close()
			return True
		except (zstd.ZstdError):
			return False

def unzstd(data):
	try:
		return zstd.decompress(data)
	except (zstd.ZstdError):
		zstd_dcmp = zstd.ZstdDecompressor()
		stream_reader = zstd_dcmp.stream_reader(data)
		decompressed = stream_reader.read()
		stream_reader.close()
		return decompressed

def is_snappy(data):
	try:
		snappy.uncompress(data)
		return True
	except (snappy.snappy.UncompressError):
		try:
			x = io.BytesIO()
			snappy.stream_decompress(io.BytesIO(data), x)
			return len(x.getvalue())>0
		except (snappy.snappy.UncompressError, OSError):
			return False

def unsnappy(data):
	try:
		return snappy.uncompress(data)
	except (snappy.snappy.UncompressError):
		x = io.BytesIO()
		snappy.stream_decompress(io.BytesIO(data), x)
		return x.getvalue()

lzo_shannon_entropy_threshold = 0.05
def is_lzo(data,safe=False):
	try:
		lzallright.LZOCompressor().decompress(data)
		return True
	except lzallright._lzallright.LZOError:
		pass
	algos = ['LZO1', 'LZO1A', 'LZO1B', 'LZO1C', 'LZO1F', 'LZO1X', 'LZO1Y', 'LZO1Z', 'LZO2A']
	for algo in algos:
		try:
			x = lzo.decompress(data,True,algorithm=algo)
			if shannon_entropy(x) > lzo_shannon_entropy_threshold:
				return algo
		except (lzo.error):
			pass
	# trying without headers
	# "safe" skips this check until this github issue is fixed
	# https://github.com/jd-boyd/python-lzo/issues/87
	if safe:
		return False
	for algo in algos:
		try:
			# Note: this can lead to segfault, underlying library has a double free
			x = lzo.decompress(data,False,5000,algorithm=algo)
			if shannon_entropy(x) > lzo_shannon_entropy_threshold:
				return algo
		except (lzo.error):
			pass
	return False

def unlzo(data):
	try:
		return lzallright.LZOCompressor().decompress(data)
	except lzallright._lzallright.LZOError:
		pass
	algos = ['LZO1', 'LZO1A', 'LZO1B', 'LZO1C', 'LZO1F', 'LZO1X', 'LZO1Y', 'LZO1Z', 'LZO2A']
	for algo in algos:
		try:
			x = lzo.decompress(data,True,algorithm=algo)
			if shannon_entropy(x) > lzo_shannon_entropy_threshold:
				return x
		except (lzo.error):
			pass
	# trying without headers
	for algo in algos:
		try:
			x = lzo.decompress(data,False,5000,algorithm=algo)
			if shannon_entropy(x) > lzo_shannon_entropy_threshold:
				return x
		except (lzo.error):
			pass

def is_quicklz(data):
	# Note: This doesnt work on my sample file from the CachedQuickLz .NET package
	try:
		quicklz.decompress(data)
		return True
	except ValueError:
		return False

def is_lzfse(data):
	# This also detects LZVN
	try:
		liblzfse.decompress(data)
		return True
	except liblzfse.error:
		return False

def is_lzw(data):
	try:
		ncompress.decompress(data)
		return True
	except ValueError:
		return False

def test_compression_methods(data, prefix):
	#gzip
	if is_gzip(data):
		print(f"{prefix}Gzip detected")
		analyse(gzip.decompress(data),f"{prefix}\t")
	#bzip2
	if is_bz2(data):
		print(f"{prefix}Bzip2 detected")
		analyse(bz2.decompress(data),f"{prefix}\t")
	#zlib
	if is_zlib(data):
		print(f"{prefix}Zlib detected")
		analyse(zlib.decompress(data),f"{prefix}\t")
	else:
		#deflate
		delfate_prefix = is_deflate(data)
		if delfate_prefix:
			print(f"{prefix}Deflate detected")
			analyse(zlib.decompressobj().decompress(delfate_prefix + data),f"{prefix}\t")
		else:
			#deflatestream
			delfate_prefix = is_deflatestream(data)
			if delfate_prefix:
				print(f"{prefix}DeflateStream detected")
				analyse(zlib.decompressobj().decompress(delfate_prefix + data[2:-4]),f"{prefix}\t")
	#lzma
	if is_lzma(data):
		print(f"{prefix}LZMA detected")
		analyse(lzma.decompress(data),f"{prefix}\t")
	#brotli
	if is_brotli(data):
		print(f"{prefix}Brotli detected")
		analyse(brotli.decompress(data),f"{prefix}\t")

	#zstd
	if is_zstd(data):
		print(f"{prefix}Zstd detected")
		analyse(unzstd(data),f"{prefix}\t")
	#lz4
	if is_lz4(data):
		print(f"{prefix}Lz4 detected")
		analyse(unlz4(data),f"{prefix}\t")
	#snappy
	if is_snappy(data):
		print(f"{prefix}Snappy detected")
		analyse(unsnappy(data),f"{prefix}\t")
	#quicklz
	if is_quicklz(data):
		print(f"{prefix}QuickLZ detected")
		analyse(quicklz.decompress(data),f"{prefix}\t")
	#lzfse
	if is_lzfse(data):
		print(f"{prefix}LZFSE/LZVN detected")
		analyse(liblzfse.decompress(data),f"{prefix}\t")
	#lzw
	if is_lzw(data):
		print(f"{prefix}LZW detected")
		analyse(ncompress.decompress(data),f"{prefix}\t")
	#lzo
	lzo_check = is_lzo(data)
	if lzo_check:
		print(f"{prefix}LZO detected ({lzo_check})")
		analyse(unlzo(data),f"{prefix}\t")

def db64(data):
	data = data.replace('\n','').replace('\r','')
	if '-' in data or '_' in data:
		return base64.urlsafe_b64decode(data)
	return base64.b64decode(data)

def is_pkcs7_padded(data):
	padding = data[-data[-1]:]
	return all(padding[b] == len(padding) for b in range(0, len(padding)))

def is_zero_padded(data):
	if len(data)%8 != 0:
		return False
	return data.endswith(b'\x00')

def get_compressions(data):
	"""Returns list of compression methods detected (no recursion)"""
	compressions = []
	funcs = {
		'gzip': is_gzip,
		'bzip2': is_bz2,
		'zlib': is_zlib,
		'deflate': is_deflate,
		'deflatestream': is_deflatestream,
		'lzma': is_lzma,
		'brotli': is_brotli,
		'zstd': is_zstd,
		'lz4': is_lz4,
		'snappy': is_snappy,
		'quicklz': is_quicklz,
		'lzfse': is_lzfse,
		'lzw': is_lzw,
		'lzo': is_lzo
	}
	if is_b64(data):
		data = base64.b64decode(data)
	elif isinstance(data,str):
		data = bytes(data)
	for key,func in funcs.items():
		# this is to skip crash-prone checks as I dont want scripts calling this get_compressions function to crash
		# but crashes when running wut directly are more acceptable.
		if key == 'lzo':
			if func(data, safe=True):
				compressions.append(key)
		else:
			if func(data):
				compressions.append(key)
	return compressions

def analyse(data,prefix=''):
	if len(data) == 0:
		print(f"{prefix}zero length reached")
		return
	# Entropy
	ent = shannon_entropy(data)
	print(f"{prefix}Shannon Entropy: {ent}")
	# Mime detection with magic
	magic_res = magic.from_buffer(data)
	if magic_res != 'data': #no point printing that out!
		print(f"{prefix}Magic Mime Detect: {magic_res}")
	# Test compression methods
	test_compression_methods(data,prefix)
	# Check padding
	if is_pkcs7_padded(data):
		print(f"{prefix}PCKS7 Padding detected, data is probably encrypted")
	if is_zero_padded(data):
		print(f"{prefix}Zero Padding detected (weak confidence), data may be encrypted")
	# Encoding Detection
	encoding_guess = chardet.detect(data)
	if encoding_guess['encoding'] != None:
		print(f"{prefix}Possible encoding: {encoding_guess['encoding']} ({encoding_guess['confidence']*100:.2f}% confidence)")
		try:
			decoded = data.decode(encoding_guess['encoding'])
		except UnicodeDecodeError:
			print(f"{prefix}Failed to decode data as {encoding_guess['encoding']}")
			return
		# Show character list
		character_list = ''.join(sorted(set(decoded)))
		print(f"{prefix}Characters used: {character_list.encode('unicode_escape').decode('utf-8')}")
		# Try base64
		if is_b64(decoded):
			print(f"{prefix}Base64 detected")
			print(f"{prefix}Running analyse function with data b64 decoded")
			b64_decoded = db64(decoded)
			analyse(b64_decoded,f"{prefix}\t")

def main():
	parser = argparse.ArgumentParser(description="wut - data identifier")
	parser.add_argument("input", nargs='?', help="input data or filename", default="/dev/stdin")
	args = parser.parse_args()
	input_data = args.input
	if sys.stdin.isatty() and args.input == '/dev/stdin':
		parser.print_help(sys.stderr)
		exit()
	if os.path.isfile(args.input) or os.path.islink(args.input):
		with open(args.input, mode='rb') as f:
			input_data = f.read()
	else:
		input_data = bytes(input_data, 'utf-8')
	analyse(input_data)

if __name__ == "__main__":
	main()
