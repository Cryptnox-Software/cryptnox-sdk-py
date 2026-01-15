# -*- coding: utf-8 -*-
"""
Module containing Python 2 compatibility utilities.

Provides type definitions, string/bytes handling, and encoding
utilities for Python 2 compatibility in cryptographic operations.
"""

import sys
import re
import binascii
import os
import hashlib

is_python2 = sys.version_info.major == 2

if sys.version_info.major == 2:
    try:
        unicode_type = unicode  # type: ignore
        long_type = long  # type: ignore
    except NameError:
        unicode_type = str
        long_type = int

    string_types = (str, unicode_type)
    string_or_bytes_types = string_types
    int_types = (int, float, long_type)

    # Base switching
    code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: ''.join([chr(x) for x in range(256)])
    }

    def bin_dbl_sha256(s):
        bytes_to_hash = from_string_to_bytes(s)
        return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg
        return symbol * (length - len(msg)) + msg

    def get_code_string(base):
        if base in code_strings:
            return code_strings[base]
        raise ValueError("Invalid base!")

    def changebase(string, frm, to, minlen=0):
        if frm == to:
            return lpad(string, get_code_string(frm)[0], minlen)
        return encode(decode(string, frm), to, minlen)

    def bin_to_b58check(inp, magicbyte=0):
        if magicbyte == 0:
            inp = '\x00' + inp
        while magicbyte > 0:
            inp = chr(int(magicbyte % 256)) + inp
            magicbyte //= 256
        leadingzbytes = len(re.match('^\x00*', inp).group(0))
        checksum = bin_dbl_sha256(inp)[:4]
        return '1' * leadingzbytes + changebase(inp+checksum, 256, 58)

    def bytes_to_hex_string(b):
        return b.encode('hex')

    def safe_from_hex(s):
        return s.decode('hex')

    def from_int_representation_to_bytes(a):
        return str(a)

    def from_int_to_byte(a):
        return chr(a)

    def from_byte_to_int(a):
        return ord(a)

    def from_bytes_to_string(s):
        return s

    def from_string_to_bytes(a):
        return a

    def safe_hexlify(a):
        return binascii.hexlify(a)

    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result = ""
        while val > 0:
            result = code_string[val % base] + result
            val //= base
        return code_string[0] * max(minlen - len(result), 0) + result

    def decode(string, base):
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += code_string.find(string[0])
            string = string[1:]
        return result

    def random_string(x):
        return os.urandom(x)

else:

    int_types = (int, float)
    string_types = (str,)

    code_strings = {
        2: '01',
        10: '0123456789',
        16: '0123456789abcdef',
        32: 'abcdefghijklmnopqrstuvwxyz234567',
        58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
        256: bytes(range(256))
    }

    def bin_dbl_sha256(s):
        if isinstance(s, str):
            s = s.encode('utf-8')
        return hashlib.sha256(hashlib.sha256(s).digest()).digest()

    def get_code_string(base):
        if base in code_strings:
            return code_strings[base]
        raise ValueError("Invalid base!")

    def lpad(msg, symbol, length):
        if len(msg) >= length:
            return msg

        # Handle bytes vs str
        if isinstance(msg, bytes):
            if isinstance(symbol, int):
                symbol = bytes([symbol])
            elif isinstance(symbol, str):
                symbol = symbol.encode('ascii')

        return symbol * (length - len(msg)) + msg

    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)

        is_bytes = isinstance(code_string, bytes)
        result = b"" if is_bytes else ""

        while val > 0:
            digit = code_string[val % base]

            if is_bytes:
                digit_char = bytes([digit])
            else:
                digit_char = digit

            result = digit_char + result
            val //= base

        padding = code_string[0]
        if is_bytes:
            padding = bytes([padding])

        return padding * max(minlen - len(result), 0) + result

    def decode(string, base):
        base = int(base)

        if base != 256 and isinstance(string, bytes):
            string = string.decode('utf-8')

        code_string = get_code_string(base)
        result = 0

        if base == 16:
            string = string.lower()

        if base == 256 and isinstance(string, bytes):
            return int.from_bytes(string, 'big')

        while len(string) > 0:
            result *= base
            char = string[0]

            if isinstance(code_string, bytes):
                if isinstance(char, str):
                    char = ord(char)
                idx = char
            else:
                idx = code_string.find(char)

            result += idx
            string = string[1:]
        return result

    def changebase(string, frm, to, minlen=0):
        if frm == to:
            return lpad(string, get_code_string(frm)[0], minlen)
        return encode(decode(string, frm), to, minlen)

    def bin_to_b58check(inp, magicbyte=0):
        if isinstance(inp, str):
            inp = inp.encode('latin-1')

        if magicbyte == 0:
            inp = b'\x00' + inp
        while magicbyte > 0:
            inp = bytes([int(magicbyte % 256)]) + inp
            magicbyte //= 256

        leadingzbytes = 0
        for x in inp:
            if x != 0:
                break
            leadingzbytes += 1

        checksum = bin_dbl_sha256(inp)[:4]

        payload = inp + checksum
        val = int.from_bytes(payload, 'big')

        result = encode(val, 58)

        return '1' * leadingzbytes + result

    def bytes_to_hex_string(b):
        if isinstance(b, str):
            return b
        return binascii.hexlify(b).decode('ascii')

    def safe_from_hex(s):
        if isinstance(s, bytes):
            s = s.decode('ascii')
        return binascii.unhexlify(s)

    def from_int_representation_to_bytes(a):
        return str(a).encode('ascii')

    def from_int_to_byte(a):
        return bytes([a])

    def from_byte_to_int(a):
        if isinstance(a, int):
            return a
        return a[0]

    def from_bytes_to_string(s):
        if isinstance(s, bytes):
            return s.decode('utf-8')
        return s

    def from_string_to_bytes(a):
        if isinstance(a, str):
            return a.encode('utf-8')
        return a

    def safe_hexlify(a):
        return binascii.hexlify(a)

    def random_string(x):
        return os.urandom(x)

    def from_jacobian(p):
        """Convert Jacobian coordinates to affine coordinates."""
        # Import P from main to avoid circular dependency
        from . import main
        z = main.inv(p[2], main.P)
        return ((p[0] * z**2) % main.P, (p[1] * z**3) % main.P)
