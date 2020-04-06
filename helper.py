import hashlib
import hmac

from base64 import b64decode, b64encode
from glob import glob
from io import BufferedIOBase
from os import unlink
from os.path import exists
from pbkdf2 import PBKDF2
from typing import Any, Dict, List, Optional, Tuple

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
PBKDF2_ROUNDS = 2048
SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3


def base64_encode(b: bytes) -> str:
    return b64encode(b).decode('ascii')


def base64_decode(s: str) -> bytes:
    return b64decode(s)


# next four functions are straight from BIP0173:
# https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
def bech32_polymod(values: List[int]) -> int:
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(s: str) -> List[int]:
    b = s.encode('ascii')
    return [x >> 5 for x in b] + [0] + [x & 31 for x in b]


def bech32_verify_checksum(hrp: str, data: List[int]) -> bool:
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def big_endian_to_int(b: bytes) -> int:
    '''little_endian_to_int takes byte sequence as a little-endian number.
    Returns an integer'''
    # use the int.from_bytes(b, <endianness>) method
    return int.from_bytes(b, 'big')


def bit_field_to_bytes(bit_field: List[int]) -> bytes:
    if len(bit_field) % 8 != 0:
        raise RuntimeError(
            'bit_field does not have a length that is divisible by 8')
    result = bytearray(len(bit_field) // 8)
    for i, bit in enumerate(bit_field):
        byte_index, bit_index = divmod(i, 8)
        if bit:
            result[byte_index] |= 1 << bit_index
    return bytes(result)


def byte_to_int(b: bytes) -> int:
    '''Returns an integer that corresponds to the byte'''
    return b[0]


def bytes_to_bit_field(some_bytes: bytes) -> List[int]:
    flag_bits = []
    # iterate over each byte of flags
    for byte in some_bytes:
        # iterate over each bit, right-to-left
        for _ in range(8):
            # add the current bit (byte & 1)
            flag_bits.append(byte & 1)
            # rightshift the byte 1
            byte >>= 1
    return flag_bits


def check_not_exists(*filenames) -> None:
    for filename in filenames:
        if exists(filename):
            raise IOError(f'file {filename} already exists')


def choice_menu(items: List[Any], exit_option: bool = False) -> Any:
    if exit_option:
        print('0. Exit')
    if len(items) == 1:
        return items[0]
    for i, item in enumerate(items):
        print(f'{i+1}. {item}')
    while True:
        choice = int(input('Please make your choice: '))
        if exit_option and choice == 0:
            return None
        if 0 <= choice - 1 < len(items):
            return items[choice - 1]


def choose_file(extension: str) -> Optional[str]:
    choices = glob(f'*.{extension}')
    if len(choices) == 0:
        print(f'No {extension} file in this directory')
        return None
    else:
        return choice_menu(choices)


def decode_base58(s: str) -> bytes:
    return raw_decode_base58(s)[1:]


def decode_bech32(s: str) -> Tuple[bool, int, bytes]:
    '''Returns whether it's testnet, segwit version and the hash from the bech32 address'''
    hrp, raw_data = s.split('1')
    if hrp == 'tb':
        testnet = True
    elif hrp == 'bc':
        testnet = False
    else:
        raise ValueError(f'unknown human readable part: {hrp}')
    data = [BECH32_ALPHABET.index(c) for c in raw_data]
    if not bech32_verify_checksum(hrp, data):
        raise ValueError(f'bad address: {s}')
    version = data[0]
    number = 0
    for digit in data[1:-6]:
        number = (number << 5) | digit
    num_bytes = (len(data) - 7) * 5 // 8
    bits_to_ignore = (len(data) - 7) * 5 % 8
    number >>= bits_to_ignore
    h = int_to_big_endian(number, num_bytes)
    if num_bytes < 2 or num_bytes > 40:
        raise ValueError(f'bytes out of range: {num_bytes}')
    return testnet, version, h


def delete_files(*filenames) -> None:
    for filename in filenames:
        if exists(filename):
            unlink(filename)


def encode_base58(s: bytes) -> str:
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    # convert from binary to hex, then hex to integer
    num = int(s.hex(), 16)
    result = ''
    prefix = '1' * count
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(raw: bytes) -> str:
    '''Takes bytes and turns it into base58 encoding with checksum'''
    # checksum is the first 4 bytes of the hash256
    checksum = hash256(raw)[:4]
    # encode_base58 on the raw and the checksum
    return encode_base58(raw + checksum)


def encode_bech32(nums: List[int]) -> str:
    '''Convert from 5-bit array of integers to bech32 format'''
    result = ''
    for n in nums:
        result += BECH32_ALPHABET[n]
    return result


def encode_bech32_checksum(s: bytes, testnet: bool = False) -> str:
    '''Convert a segwit ScriptPubKey to a bech32 address'''
    if testnet:
        prefix = 'tb'
    else:
        prefix = 'bc'
    version = s[0]
    if version > 0:
        version -= 0x50
    length = s[1]
    data = [version] + group_32(s[2:2 + length])
    checksum = bech32_create_checksum(prefix, data)
    bech32 = encode_bech32(data + checksum)
    return prefix + '1' + bech32


def encode_dict(d: Dict[bytes, Any]) -> bytes:
    return encode_list(d.values())


def encode_list(l: Any) -> bytes:
    result = encode_varint(len(l))
    for item in l:
        result += item.serialize()
    return result


def encode_varint(i: int) -> bytes:
    '''encodes an integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise RuntimeError(f'integer too large: {i}')


def encode_varstr(b: bytes) -> bytes:
    '''encodes bytes as a varstr'''
    # encode the length of the string using encode_varint
    result = encode_varint(len(b))
    # add the bytes
    result += b
    # return the whole thing
    return result


def group_32(s: bytes) -> List[int]:
    '''Convert from 8-bit bytes to 5-bit array of integers'''
    result = []
    unused_bits = 0
    current = 0
    for c in s:
        unused_bits += 8
        current = (current << 8) + c
        while unused_bits > 5:
            unused_bits -= 5
            result.append(current >> unused_bits)
            mask = (1 << unused_bits) - 1
            current &= mask
    result.append(current << (5 - unused_bits))
    return result


def hash160(s: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    return hmac.HMAC(key=key, msg=msg, digestmod=hashlib.sha512).digest()


def hmac_sha512_kdf(msg: str, salt: bytes) -> bytes:
    return PBKDF2(
        msg,
        salt,
        iterations=PBKDF2_ROUNDS,
        macmodule=hmac,
        digestmodule=hashlib.sha512,
    ).read(64)


def int_to_big_endian(n: int, length: int) -> bytes:
    '''int_to_little_endian takes an integer and returns the little-endian
    byte sequence of length'''
    # use the int.to_bytes(length, <endianness>) method
    return n.to_bytes(length, 'big')


def int_to_byte(n: int) -> bytes:
    '''Returns a single byte that corresponds to the integer'''
    if n > 255 or n < 0:
        raise ValueError(
            'integer greater than 255 or lower than 0 cannot be converted into a byte'
        )
    return bytes([n])


def int_to_little_endian(n: int, length: int) -> bytes:
    '''int_to_little_endian takes an integer and returns the little-endian
    byte sequence of length'''
    # use the int.to_bytes(length, <endianness>) method
    return n.to_bytes(length, 'little')


def little_endian_to_int(b: bytes) -> int:
    '''little_endian_to_int takes byte sequence as a little-endian number.
    Returns an integer'''
    # use the int.from_bytes(b, <endianness>) method
    return int.from_bytes(b, 'little')


def merkle_parent(hash1: bytes, hash2: bytes) -> bytes:
    '''Takes the binary hashes and calculates the hash256'''
    # return the hash256 of hash1 + hash2
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes: List[bytes]) -> List[bytes]:
    '''Takes a list of binary hashes and returns a list that's half
    the length'''
    # if the list has exactly 1 element raise an error
    if len(hashes) == 1:
        raise RuntimeError('Cannot take a parent level with only 1 item')
    # if the list has an odd number of elements, duplicate the last one
    #       and put it at the end so it has an even number of elements
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    # initialize parent level
    parent_level = []
    # loop over every pair (use: for i in range(0, len(hashes), 2))
    for i in range(0, len(hashes), 2):
        # get the merkle parent of i and i+1 hashes
        parent = merkle_parent(hashes[i], hashes[i + 1])
        # append parent to parent level
        parent_level.append(parent)
    # return parent level
    return parent_level


def merkle_root(hashes: List[bytes]) -> bytes:
    '''Takes a list of binary hashes and returns the merkle root
    '''
    # current level starts as hashes
    current_level = hashes
    # loop until there's exactly 1 element
    while len(current_level) > 1:
        # current level becomes the merkle parent level
        current_level = merkle_parent_level(current_level)
    # return the 1st item of current_level
    return current_level[0]


def murmur3(data: bytes, seed: int = 0) -> int:
    '''from http://stackoverflow.com/questions/13305290/is-there-a-pure-python-implementation-of-murmurhash'''
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    length = len(data)
    h1 = seed
    roundedEnd = (length & 0xfffffffc)  # round down to 4 byte block
    for i in range(0, roundedEnd, 4):
        # little endian load order
        k1 = (data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) | \
            ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
        h1 = (h1 << 13) | ((h1 & 0xffffffff) >> 19)  # ROTL32(h1,13)
        h1 = h1 * 5 + 0xe6546b64
    # tail
    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[roundedEnd + 2] & 0xff) << 16
    # fallthrough
    if val in [2, 3]:
        k1 |= (data[roundedEnd + 1] & 0xff) << 8
    # fallthrough
    if val in [1, 2, 3]:
        k1 |= data[roundedEnd] & 0xff
        k1 *= c1
        k1 = (k1 << 15) | ((k1 & 0xffffffff) >> 17)  # ROTL32(k1,15)
        k1 *= c2
        h1 ^= k1
    # finalization
    h1 ^= length
    # fmix(h1)
    h1 ^= ((h1 & 0xffffffff) >> 16)
    h1 *= 0x85ebca6b
    h1 ^= ((h1 & 0xffffffff) >> 13)
    h1 *= 0xc2b2ae35
    h1 ^= ((h1 & 0xffffffff) >> 16)
    return h1 & 0xffffffff


def raw_decode_base58(s: str) -> bytes:
    num = 0
    # see how many leading 0's we are starting with
    prefix = b''
    for c in s:
        if num == 0 and c == '1':
            prefix += b'\x00'
        else:
            num = 58 * num + BASE58_ALPHABET.index(c)
    # put everything into base64
    byte_array = []
    while num > 0:
        byte_array.insert(0, num & 255)
        num >>= 8
    combined = prefix + bytes(byte_array)
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise RuntimeError(f'bad address: {checksum} {hash256(combined)[:4]}')
    return combined[:-4]


def read_dict(s: BufferedIOBase, cls: Any) -> Dict[bytes, Any]:
    return {item.key(): item for item in read_list(s, cls)}


def read_list(s: BufferedIOBase, cls: Any) -> Any:
    num_items = read_varint(s)
    return [cls.parse(s) for _ in range(num_items)]


def read_varint(s: BufferedIOBase) -> int:
    '''reads a variable integer from a stream'''
    b = s.read(1)
    if len(b) != 1:
        raise IOError('stream has no bytes')
    i = b[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def read_varstr(s: BufferedIOBase) -> bytes:
    '''reads a variable string from a stream'''
    # remember that s.read(n) will read n bytes from the stream
    # find the length of the string by using read_varint on the string
    item_length = read_varint(s)
    # read that many bytes from the stream
    return s.read(item_length)


def serialize_key_value(key: bytes, value: bytes) -> bytes:
    return encode_varstr(key) + encode_varstr(value)


def sha256(s: bytes) -> bytes:
    return hashlib.sha256(s).digest()
