# -*- coding: utf-8 -*-
"""
Module containing Python 3 specific cryptographic implementations.

Provides Python 3 optimized cryptographic functions including
elliptic curve operations, ECDSA signing/verification, and
mathematical utilities for secp256k1 operations.
"""

import sys
import os
import binascii
import hashlib


if sys.version_info.major == 3:
    string_or_bytes_types = (str, bytes)
    int_types = (int, float)
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
            inp = from_int_to_byte(0) + inp
        while magicbyte > 0:
            inp = from_int_to_byte(magicbyte % 256) + inp
            magicbyte //= 256

        leadingzbytes = 0
        for x in inp:
            if x != 0:
                break
            leadingzbytes += 1

        checksum = bin_dbl_sha256(inp)[:4]
        return '1' * leadingzbytes + changebase(inp+checksum, 256, 58)

    def bytes_to_hex_string(b):
        if isinstance(b, str):
            return b

        return ''.join(f'{y:02x}' for y in b)

    def safe_from_hex(s):
        return bytes.fromhex(s)

    def from_int_representation_to_bytes(a):
        return bytes(str(a), 'utf-8')

    def from_int_to_byte(a):
        return bytes([a])

    def from_byte_to_int(a):
        return a

    def from_string_to_bytes(a):
        return a if isinstance(a, bytes) else bytes(a, 'utf-8')

    def safe_hexlify(a):
        return str(binascii.hexlify(a), 'utf-8')

    def encode(val, base, minlen=0):
        base, minlen = int(base), int(minlen)
        code_string = get_code_string(base)
        result_bytes = bytes()
        while val > 0:
            curcode = code_string[val % base]
            result_bytes = bytes([ord(curcode)]) + result_bytes
            val //= base

        pad_size = minlen - len(result_bytes)

        padding_element = b'\x00' if base == 256 else b'1' \
            if base == 58 else b'0'
        if pad_size > 0:
            result_bytes = padding_element*pad_size + result_bytes

        result_string = ''.join([chr(y) for y in result_bytes])
        result = result_bytes if base == 256 else result_string

        return result

    def decode(string, base):
        if base == 256 and isinstance(string, str):
            string = bytes(bytearray.fromhex(string))
        base = int(base)
        code_string = get_code_string(base)
        result = 0
        if base == 256:
            def extract(d, _cs):
                return d
        else:
            def extract(d, cs):
                return cs.find(d if isinstance(d, str) else chr(d))

        if base == 16:
            string = string.lower()
        while len(string) > 0:
            result *= base
            result += extract(string[0], code_string)
            string = string[1:]
        return result

    def random_string(x):
        return str(os.urandom(x))

    def from_jacobian(p):
        """Convert Jacobian coordinates to affine coordinates."""
        # Import P from main to avoid circular dependency
        from . import main
        z = main.inv(p[2], main.P)
        return ((p[0] * z**2) % main.P, (p[1] * z**3) % main.P)

    def multiply(pubkey, privkey):
        """Multiply a public key by a scalar (private key)."""
        from . import main
        if isinstance(privkey, int):
            privkey_int = privkey
        else:
            privkey_int = main.decode_privkey(privkey)

        # Decode public key to get the point
        if isinstance(pubkey, tuple):
            point = pubkey
        else:
            point = main.decode_pubkey(pubkey)

        # Fast multiplication using double-and-add algorithm
        if privkey_int == 0:
            return (0, 0)
        if privkey_int == 1:
            return point

        # Convert to Jacobian coordinates for faster computation
        result = (0, 0, 1)  # Point at infinity in Jacobian
        addend = main.to_jacobian(point)

        while privkey_int:
            if privkey_int & 1:
                result = main.jacobian_add(result, addend)
            addend = main.jacobian_double(addend)
            privkey_int >>= 1

        # Convert back to affine coordinates
        return from_jacobian(result)

    def ecdsa_raw_verify(msghash, sig, pub):
        """Verify ECDSA signature."""
        from . import main
        from . import py2specials

        if isinstance(msghash, bytes):
            msghash = py2specials.decode(msghash, 256)

        _, r, s = sig

        # Decode public key
        if not isinstance(pub, tuple):
            pub = main.decode_pubkey(pub)

        w = main.inv(s, main.N)
        z = msghash

        u1 = (z * w) % main.N
        u2 = (r * w) % main.N

        # Calculate point: u1*G + u2*pub
        point1 = multiply(main.G, u1)
        point2 = multiply(pub, u2)
        point = main.fast_add(point1, point2)

        return point[0] == r

    def ecdsa_recover(msg, sig):
        """Recover public key from ECDSA signature."""
        from . import main
        from . import py2specials

        if isinstance(msg, str):
            msg = msg.encode('utf-8')

        msghash = main.electrum_sig_hash(msg)

        if isinstance(sig, str):
            v, r, _s = main.decode_sig(sig)
        else:
            v, r, _s = sig

        # Recovery parameter
        x = r

        # Calculate y from x
        beta = pow(int(x * x * x + main.A * x + main.B), int((main.P + 1) // 4), int(main.P))
        y = beta if (v - 27) % 2 == beta % 2 else (main.P - beta)

        # Recovered point R
        R = (x, y)

        # Calculate public key: (r*R - z*G) / r
        e = py2specials.decode(msghash, 256)

        # Calculate -e*G
        minus_e = main.N - e
        eG = multiply(main.G, minus_e)

        # Calculate r*R
        rR = multiply(R, r)

        # Add the points
        numerator = main.fast_add(rR, eG)

        # Divide by r (multiply by r^-1)
        r_inv = main.inv(r, main.N)
        pubkey = multiply(numerator, r_inv)

        return pubkey
