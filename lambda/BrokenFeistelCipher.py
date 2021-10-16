#!/usr/bin/python3
#	frankenticket - Illustrating the importance of proper authentication
#	Copyright (C) 2021-2021 Johannes Bauer
#
#	This file is part of frankenticket.
#
#	frankenticket is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	frankenticket is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with frankenticket; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import hashlib

class BrokenFeistelCipher():
	"""This is a cryptographically broken Feistel cipher that is based on MD5.
	It is used purely for educational purposes as a replacement for AES-128-ECB
	so that this demo can be easily deployed using native Python.

	Key size is arbitrary and block size is 128 bit (16 bytes).
	"""
	def __init__(self, key):
		self._subkeys = self._derive_subkeys(key, 20)

	@staticmethod
	def _derive_subkeys(key, rounds):
		k = hashlib.md5(key).digest()
		keys = [ ]
		for i in range(rounds):
			k = hashlib.md5(k).digest()
			keys.append(k)
		return keys

	@staticmethod
	def _apply_round(subkey, data):
		return hashlib.md5(subkey + data).digest()

	@staticmethod
	def _xor(a, b):
		return bytes(x ^ y for (x, y) in zip(a, b))

	def encrypt(self, block):
		(l_n, r_n) = (block[ : 8], block[8 : ])
		for subkey in self._subkeys:
			rk = self._apply_round(subkey, r_n)[:8]
			(r_n, l_n) = (self._xor(l_n, rk), r_n)
		return l_n + r_n

	def decrypt(self, block):
		(r_n, l_n) = (block[ : 8], block[8 : ])
		for subkey in reversed(self._subkeys):
			rk = self._apply_round(subkey, r_n)[:8]
			(r_n, l_n) = (self._xor(l_n, rk), r_n)
		return r_n + l_n

if __name__ == "__main__":
	bfc = BrokenFeistelCipher(b"foobarx")
	ciphertext = bfc.encrypt(bytes(range(16)))
	print(ciphertext.hex())
	print(bfc.decrypt(ciphertext).hex())
