from __future__ import annotations
from io import BufferedIOBase
from secrets import token_bytes
from typing import Optional

from cipher import CPCipher
from helper import (
    big_endian_to_int,
    encode_base58_checksum,
    encode_varstr,
    hash160,
    hash256,
    raw_decode_base58,
    read_varstr,
    sha256,
)
from _libsec import ffi, lib

GLOBAL_CTX = ffi.gc(
    lib.secp256k1_context_create(lib.SECP256K1_CONTEXT_SIGN
                                 | lib.SECP256K1_CONTEXT_VERIFY),
    lib.secp256k1_context_destroy)
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


class S256Point:
    def __init__(self,
                 csec: Optional[bytes] = None,
                 usec: Optional[bytes] = None) -> None:
        if usec:
            self.usec = usec
            self.csec = None
            sec_cache = usec
        elif csec:
            self.csec = csec
            self.usec = None
            sec_cache = csec
        else:
            raise IOError('need a serialization')
        self.c = ffi.new('secp256k1_pubkey *')
        if not lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, self.c, sec_cache,
                                             len(sec_cache)):
            raise RuntimeError(f'libsecp256k1 produced error {csec} {usec}')

    def __add__(self, scalar: int) -> S256Point:
        '''Multiplies scalar by generator, adds result to current point'''
        coef = scalar % N
        new_key = ffi.new('secp256k1_pubkey *')
        s = self.sec(compressed=False)
        lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, new_key, s, len(s))
        lib.secp256k1_ec_pubkey_tweak_add(GLOBAL_CTX, new_key,
                                          coef.to_bytes(32, 'big'))
        serialized = ffi.new('unsigned char [65]')
        output_len = ffi.new('size_t *', 65)
        lib.secp256k1_ec_pubkey_serialize(GLOBAL_CTX, serialized, output_len,
                                          new_key,
                                          lib.SECP256K1_EC_UNCOMPRESSED)
        return self.__class__(usec=bytes(serialized))

    def __eq__(self, other: S256Point) -> bool:
        return self.sec() == other.sec()

    def __repr__(self) -> str:
        return f'S256Point({self.sec(compressed=False).hex()})'

    def __rmul__(self, coefficient: int) -> S256Point:
        coef = coefficient % N
        new_key = ffi.new('secp256k1_pubkey *')
        s = self.sec(compressed=False)
        lib.secp256k1_ec_pubkey_parse(GLOBAL_CTX, new_key, s, len(s))
        lib.secp256k1_ec_pubkey_tweak_mul(GLOBAL_CTX, new_key,
                                          coef.to_bytes(32, 'big'))
        serialized = ffi.new('unsigned char [65]')
        output_len = ffi.new('size_t *', 65)
        lib.secp256k1_ec_pubkey_serialize(GLOBAL_CTX, serialized, output_len,
                                          new_key,
                                          lib.SECP256K1_EC_UNCOMPRESSED)
        return self.__class__(usec=bytes(serialized))

    @classmethod
    def parse(self, sec_bin: bytes) -> S256Point:
        '''returns a Point object from a SEC binary (not hex)'''
        if sec_bin[0] == 4:
            return S256Point(usec=sec_bin)
        else:
            return S256Point(csec=sec_bin)

    def encrypt_message(self, message: bytes) -> bytes:
        k = big_endian_to_int(token_bytes(32))
        private_key = PrivateKey(k)
        cipher = private_key.cipher(self)
        encrypted = cipher.encrypt(message)
        return private_key.point.sec() + encode_varstr(encrypted)

    def hash160(self, compressed: bool = True) -> bytes:
        return hash160(self.sec(compressed))

    def sec(self, compressed: bool = True) -> bytes:
        '''returns the binary version of the SEC format'''
        if compressed:
            if not self.csec:
                serialized = ffi.new('unsigned char [33]')
                output_len = ffi.new('size_t *', 33)

                lib.secp256k1_ec_pubkey_serialize(
                    GLOBAL_CTX,
                    serialized,
                    output_len,
                    self.c,
                    lib.SECP256K1_EC_COMPRESSED,
                )
                self.csec = bytes(ffi.buffer(serialized, 33))
            return self.csec
        else:
            if not self.usec:
                serialized = ffi.new('unsigned char [65]')
                output_len = ffi.new('size_t *', 65)

                lib.secp256k1_ec_pubkey_serialize(
                    GLOBAL_CTX,
                    serialized,
                    output_len,
                    self.c,
                    lib.SECP256K1_EC_UNCOMPRESSED,
                )
                self.usec = bytes(ffi.buffer(serialized, 65))
            return self.usec

    def verify(self, z: int, sig: Signature) -> int:
        msg = z.to_bytes(32, 'big')
        return lib.secp256k1_ecdsa_verify(GLOBAL_CTX, sig.c, msg, self.c)

    def verify_message(self, message: bytes, sig: Signature) -> int:
        '''Verify a message in the form of bytes. Assumes that the z
        is calculated using hash256 interpreted as a big-endian integer'''
        # calculate the hash256 of the message
        h256 = hash256(message)
        # z is the big-endian interpretation. use big_endian_to_int
        z = big_endian_to_int(h256)
        # verify the message using the self.verify method
        return self.verify(z, sig)


G = S256Point(usec=bytes.fromhex(
    '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
))


class Signature:
    def __init__(self, der: Optional[bytes] = None, c: None = None) -> None:
        if der:
            self.der_cache = der
            self.c = ffi.new('secp256k1_ecdsa_signature *')
            if not lib.secp256k1_ecdsa_signature_parse_der(
                    GLOBAL_CTX, self.c, der, len(der)):
                raise RuntimeError(f'badly formatted signature {der.hex()}')
        elif c:
            self.c = c
            self.der_cache = None
        else:
            raise RuntimeError('need der or c object')

    def __eq__(self, other: Signature) -> bool:
        return self.der() == other.der()

    def __repr__(self) -> str:
        return 'Signature({self.der().hex()})'

    def der(self) -> bytes:
        if not self.der_cache:
            der = ffi.new('unsigned char[72]')
            der_length = ffi.new('size_t *', 72)
            lib.secp256k1_ecdsa_signature_serialize_der(
                GLOBAL_CTX, der, der_length, self.c)
            self.der_cache = bytes(ffi.buffer(der, der_length[0]))
        return self.der_cache


class PrivateKey:
    def __init__(self, secret: int, testnet: bool = False) -> None:
        self.secret = secret
        self.point = secret * G
        self.testnet = testnet

    def __eq__(self, other: PrivateKey) -> bool:
        return self.wif() == other.wif()

    @classmethod
    def parse(cls, wif: str) -> PrivateKey:
        '''Converts WIF to a PrivateKey object'''
        raw = raw_decode_base58(wif)
        if len(raw) == 34:  # compressed
            if raw[-1] != 1:
                raise ValueError('Invalid WIF')
            raw = raw[:-1]
        secret = big_endian_to_int(raw[1:])
        if raw[0] == 0xef:
            testnet = True
        elif raw[0] == 0x80:
            testnet = False
        else:
            raise ValueError('Invalid WIF')
        return cls(secret, testnet=testnet)

    def cipher(self, other_point: S256Point) -> CPCipher:
        '''Returns a cipher and the prefix needed by the owner of
        the private key to decrypt this message'''
        shared_secret = sha256((self.secret * other_point).sec())
        return CPCipher(shared_secret)

    def decrypt_message(self, s: BufferedIOBase) -> bytes:
        cipher = self.cipher(S256Point.parse(s.read(33)))
        return cipher.decrypt(read_varstr(s))

    def sign(self, z: int) -> Signature:
        secret = self.secret.to_bytes(32, 'big')
        msg = z.to_bytes(32, 'big')
        csig = ffi.new('secp256k1_ecdsa_signature *')
        if not lib.secp256k1_ecdsa_sign(GLOBAL_CTX, csig, msg, secret,
                                        ffi.NULL, ffi.NULL):
            raise RuntimeError(
                'something went wrong with c signing')  # pragma: no cover
        sig = Signature(c=csig)
        if not self.point.verify(z, sig):
            raise RuntimeError(
                'something went wrong with signing')  # pragma: no cover
        return sig

    def sign_message(self, message: bytes) -> Signature:
        '''Sign a message in the form of bytes instead of the z. The z should
        be assumed to be the hash256 of the message interpreted as a big-endian
        integer.'''
        # compute the hash256 of the message
        h256 = hash256(message)
        # z is the big-endian interpretation. use big_endian_to_int
        z = big_endian_to_int(h256)
        # sign the message using the self.sign method
        return self.sign(z)

    def wif(self, compressed: bool = True) -> str:
        # convert the secret from integer to a 32-bytes in big endian using num.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        # prepend b'\xef' on testnet, b'\x80' on mainnet
        if self.testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        # append b'\x01' if compressed
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        # encode_base58_checksum the whole thing
        return encode_base58_checksum(prefix + secret_bytes + suffix)
