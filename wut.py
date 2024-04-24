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
		lzma.decompress(data)
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
	#lzma
	if is_lzma(data):
		print(f"{prefix}LZMA detected")
		analyse(lzma.decompress(data),f"{prefix}\t")
	#brotli
	if is_brotli(data):
		print(f"{prefix}Brotli detected")
		analyse(brotli.decompress(data),f"{prefix}\t")
	#deflate
	delfate_prefix = is_deflate(data)
	if delfate_prefix:
		print(f"{prefix}Deflate detected")
		analyse(zlib.decompressobj().decompress(delfate_prefix + data),f"{prefix}\t")

def db64(data):
	data = data.replace('\n','').replace('\r','')
	if '-' in data or '_' in data:
		return base64.urlsafe_b64encode(data)
	return base64.b64decode(data)

def is_pkcs7_padded(data):
	padding = data[-data[-1]:]
	return all(padding[b] == len(padding) for b in range(0, len(padding)))

def is_zero_padded(data):
	if len(data)%8 != 0:
		return False
	return data.endswith(b'\x00')

def analyse(data,prefix=''):
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
		print(f"PCKS7 Padding detected, data is probably encrypted")
	if is_zero_padded(data):
		print(f"Zero Padding detected (weak confidence), data may be encrypted")
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

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="wut - data identifier")
	parser.add_argument("input", help="input data or filename")
	args = parser.parse_args()
	input_data = args.input
	if os.path.isfile(args.input) or os.path.islink(args.input):
		with open(args.input, mode='rb') as f:
			input_data = f.read()
	else:
		input_data = bytes(input_data, 'utf-8')
	analyse(input_data)
