import hashlib
from typing import List

from ecc import (
    S256Point,
    Signature,
)
from helper import (
    hash160,
    hash256,
)
from timelock import Locktime, Sequence


def is_number_op_code(op_code: bytes) -> bool:
    return op_code in OP_CODE_TO_NUMBER


def number_to_op_code(n: int) -> bytes:
    '''Returns the op code number for a particular number'''
    if NUMBER_TO_OP_CODE.get(n) is None:
        raise ValueError(f'No OP code exists for {n}')
    return NUMBER_TO_OP_CODE[n]


def op_code_to_number(op_code: bytes) -> int:
    '''Returns the n for a particular OP code'''
    if OP_CODE_TO_NUMBER.get(op_code) is None:
        raise ValueError(f'Not a number OP code: {op_code.hex()}')
    return OP_CODE_TO_NUMBER[op_code]


def encode_minimal_num(n: int) -> bytes:
    if -1 <= n <= 16:
        return number_to_op_code(n)
    else:
        return encode_num(n)


def decode_minimal_num(n: bytes) -> int:
    if is_number_op_code(n):
        return op_code_to_number(n)
    else:
        return decode_num(n)


def encode_num(num: int) -> bytes:
    if num == 0:
        return OP_0
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    while abs_num:
        result.append(abs_num & 0xff)
        abs_num >>= 8
    # if the top bit is set,
    # for negative numbers we ensure that the top bit is set
    # for positive numbers we ensure that the top bit is not set
    if result[-1] & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_num(element: bytes) -> int:
    if element == OP_0:
        return 0
    # reverse for big endian
    big_endian = element[::-1]
    # top bit being 1 means it's negative
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result


def op_0(stack: List[bytes]) -> bool:
    stack.append(encode_num(0))
    return True


def op_1negate(stack: List[bytes]) -> bool:
    stack.append(encode_num(-1))
    return True


def op_1(stack: List[bytes]) -> bool:
    stack.append(encode_num(1))
    return True


def op_2(stack: List[bytes]) -> bool:
    stack.append(encode_num(2))
    return True


def op_3(stack: List[bytes]) -> bool:
    stack.append(encode_num(3))
    return True


def op_4(stack: List[bytes]) -> bool:
    stack.append(encode_num(4))
    return True


def op_5(stack: List[bytes]) -> bool:
    stack.append(encode_num(5))
    return True


def op_6(stack: List[bytes]) -> bool:
    stack.append(encode_num(6))
    return True


def op_7(stack: List[bytes]) -> bool:
    stack.append(encode_num(7))
    return True


def op_8(stack: List[bytes]) -> bool:
    stack.append(encode_num(8))
    return True


def op_9(stack: List[bytes]) -> bool:
    stack.append(encode_num(9))
    return True


def op_10(stack: List[bytes]) -> bool:
    stack.append(encode_num(10))
    return True


def op_11(stack: List[bytes]) -> bool:
    stack.append(encode_num(11))
    return True


def op_12(stack: List[bytes]) -> bool:
    stack.append(encode_num(12))
    return True


def op_13(stack: List[bytes]) -> bool:
    stack.append(encode_num(13))
    return True


def op_14(stack: List[bytes]) -> bool:
    stack.append(encode_num(14))
    return True


def op_15(stack: List[bytes]) -> bool:
    stack.append(encode_num(15))
    return True


def op_16(stack: List[bytes]) -> bool:
    stack.append(encode_num(16))
    return True


def op_nop(stack: List[bytes]) -> bool:
    return True


def op_if(stack: List[bytes], items: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (OP_IF, OP_NOTIF):
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == OP_ELSE:
            current_array = false_items
        elif item == OP_ENDIF:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        items[:0] = false_items
    else:
        items[:0] = true_items
    return True


def op_notif(stack: List[bytes], items: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    # go through and re-make the items array based on the top stack element
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):
            # nested if, we have to go another endif
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:
            current_array = false_items
        elif item == 104:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        items[:0] = true_items
    else:
        items[:0] = false_items
    return True


def op_verify(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        return False
    return True


def op_return(stack: List[bytes]) -> bool:
    return False


def op_toaltstack(stack: List[bytes], altstack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    altstack.append(stack.pop())
    return True


def op_fromaltstack(stack: List[bytes], altstack: List[bytes]) -> bool:
    if len(altstack) < 1:
        return False
    stack.append(altstack.pop())
    return True


def op_2drop(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    stack.pop()
    stack.pop()
    return True


def op_2dup(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    stack.extend(stack[-2:])
    return True


def op_3dup(stack: List[bytes]) -> bool:
    if len(stack) < 3:
        return False
    stack.extend(stack[-3:])
    return True


def op_2over(stack: List[bytes]) -> bool:
    if len(stack) < 4:
        return False
    stack.extend(stack[-4:-2])
    return True


def op_2rot(stack: List[bytes]) -> bool:
    if len(stack) < 6:
        return False
    stack.extend(stack[-6:-4])
    return True


def op_2swap(stack: List[bytes]) -> bool:
    if len(stack) < 4:
        return False
    stack[-4:] = stack[-2:] + stack[-4:-2]
    return True


def op_ifdup(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    if decode_num(stack[-1]) != 0:
        stack.append(stack[-1])
    return True


def op_depth(stack: List[bytes]) -> bool:
    stack.append(encode_num(len(stack)))
    return True


def op_drop(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    stack.pop()
    return True


def op_dup(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    stack.append(stack[-1])
    return True


def op_nip(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    stack[-2:] = stack[-1:]
    return True


def op_over(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    stack.append(stack[-2])
    return True


def op_pick(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    stack.append(stack[-n - 1])
    return True


def op_roll(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    if n == 0:
        return True
    stack.append(stack.pop(-n - 1))
    return True


def op_rot(stack: List[bytes]) -> bool:
    if len(stack) < 3:
        return False
    stack.append(stack.pop(-3))
    return True


def op_swap(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    stack.append(stack.pop(-2))
    return True


def op_tuck(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    stack.insert(-2, stack[-1])
    return True


def op_size(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    stack.append(encode_num(len(stack[-1])))
    return True


def op_equal(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = stack.pop()
    element2 = stack.pop()
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_equalverify(stack: List[bytes]) -> bool:
    return op_equal(stack) and op_verify(stack)


def op_1add(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element + 1))
    return True


def op_1sub(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element - 1))
    return True


def op_negate(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(-element))
    return True


def op_abs(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    if element < 0:
        stack.append(encode_num(-element))
    else:
        stack.append(encode_num(element))
    return True


def op_not(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_0notequal(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_add(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element1 + element2))
    return True


def op_sub(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element2 - element1))
    return True


def op_booland(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 and element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_boolor(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 or element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequal(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequalverify(stack: List[bytes]) -> bool:
    return op_numequal(stack) and op_verify(stack)


def op_numnotequal(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_lessthan(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 < element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthan(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 > element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_lessthanorequal(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 <= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthanorequal(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 >= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_min(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 < element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_max(stack: List[bytes]) -> bool:
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 > element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_within(stack: List[bytes]) -> bool:
    if len(stack) < 3:
        return False
    maximum = decode_num(stack.pop())
    minimum = decode_num(stack.pop())
    element = decode_num(stack.pop())
    if element >= minimum and element < maximum:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_ripemd160(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.new('ripemd160', element).digest())
    return True


def op_sha1(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha1(element).digest())
    return True


def op_sha256(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha256(element).digest())
    return True


def op_hash160(stack: List[bytes]) -> bool:
    # check to see if there's at least 1 element
    if len(stack) < 1:
        return False
    # get the element on the top with stack.pop()
    element = stack.pop()
    # add the hash160 of the element to the end of the stack
    h160 = hash160(element)
    stack.append(h160)
    return True


def op_hash256(stack: List[bytes]) -> bool:
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True


def op_checksig(stack: List[bytes], z: int) -> bool:
    # check to see if there's at least 2 elements
    if len(stack) < 2:
        return False
    # get the sec_pubkey with stack.pop()
    sec_pubkey = stack.pop()
    # get the der_signature with stack.pop()[:-1] (last byte is removed)
    der_signature = stack.pop()[:-1]
    # parse the sec format pubkey with S256Point
    point = S256Point.parse(sec_pubkey)
    # parse the der format signature with Signature
    sig = Signature(der_signature)
    # verify using the point, z and signature
    # if verified add encode_num(1) to the end, otherwise encode_num(0)
    if point.verify(z, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_checksigverify(stack: List[bytes], z: int) -> bool:
    return op_checksig(stack, z) and op_verify(stack)


def op_checkmultisig(stack: List[bytes], z: int) -> bool:
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = decode_num(stack.pop())
    if len(stack) < m + 1:
        return False
    der_signatures = []
    for _ in range(m):
        # signature is assumed to be using SIGHASH_ALL
        der_signatures.append(stack.pop()[:-1])
    # OP_CHECKMULTISIG bug
    stack.pop()
    try:
        # parse the sec pubkeys into an array of points
        points = [S256Point.parse(sec) for sec in sec_pubkeys]
        # parse the der_signatures into an array of signatures
        sigs = [Signature(der) for der in der_signatures]
        # loop through the signatures
        for sig in sigs:
            # bail early if we don't have any points left
            if len(points) == 0:
                print("signatures no good or not in right order")
                return False
            # while we have points
            while points:
                # get the point at the front (points.pop(0))
                point = points.pop(0)
                # see if this point can verify this sig with this z
                if point.verify(z, sig):
                    # break if so, this sig is valid!
                    break
        # if we made it this far, we have to add a 1 to the stack
        # use encode_num(1)
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True


def op_checkmultisigverify(stack: List[bytes], z: int) -> bool:
    return op_checkmultisig(stack, z) and op_verify(stack)


def op_checklocktimeverify(stack: List[bytes], locktime: Locktime, sequence: Sequence) -> bool:
    if sequence.is_max():
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    stack_locktime = Locktime(element)
    if not locktime.comparable(stack_locktime):
        return False
    if locktime.less_than(stack_locktime):
        return False
    return True


def op_checksequenceverify(stack: List[bytes], version: int, sequence: Sequence) -> bool:
    if not sequence.relative():
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    if version < 2:
        return False
    stack_sequence = Sequence(element)
    if not sequence.comparable(stack_sequence):
        return False
    if sequence.less_than(stack_sequence):
        return False
    return True


OP_0 = b''
OP_PUSHDATA1 = bytes([76])
OP_PUSHDATA2 = bytes([77])
OP_PUSHDATA4 = bytes([78])
OP_1NEGATE = bytes([79])
OP_1 = bytes([81])
OP_2 = bytes([82])
OP_3 = bytes([83])
OP_4 = bytes([84])
OP_5 = bytes([85])
OP_6 = bytes([86])
OP_7 = bytes([87])
OP_8 = bytes([88])
OP_9 = bytes([89])
OP_10 = bytes([90])
OP_11 = bytes([91])
OP_12 = bytes([92])
OP_13 = bytes([93])
OP_14 = bytes([94])
OP_15 = bytes([95])
OP_16 = bytes([96])
OP_NOP = bytes([97])
OP_IF = bytes([99])
OP_NOTIF = bytes([100])
OP_ELSE = bytes([103])
OP_ENDIF = bytes([104])
OP_VERIFY = bytes([105])
OP_RETURN = bytes([106])
OP_TOALTSTACK = bytes([107])
OP_FROMALTSTACK = bytes([108])
OP_2DROP = bytes([109])
OP_2DUP = bytes([110])
OP_3DUP = bytes([111])
OP_2OVER = bytes([112])
OP_2ROT = bytes([113])
OP_2SWAP = bytes([114])
OP_IFDUP = bytes([115])
OP_DEPTH = bytes([116])
OP_DROP = bytes([117])
OP_DUP = bytes([118])
OP_NIP = bytes([119])
OP_OVER = bytes([120])
OP_PICK = bytes([121])
OP_ROLL = bytes([122])
OP_ROT = bytes([123])
OP_SWAP = bytes([124])
OP_TUCK = bytes([125])
OP_SIZE = bytes([130])
OP_EQUAL = bytes([135])
OP_EQUALVERIFY = bytes([136])
OP_1ADD = bytes([139])
OP_1SUB = bytes([140])
OP_NEGATE = bytes([143])
OP_ABS = bytes([144])
OP_NOT = bytes([145])
OP_0NOTEQUAL = bytes([146])
OP_ADD = bytes([147])
OP_SUB = bytes([148])
OP_BOOLAND = bytes([154])
OP_BOOLOR = bytes([155])
OP_NUMEQUAL = bytes([156])
OP_NUMEQUALVERIFY = bytes([157])
OP_NUMNOTEQUAL = bytes([158])
OP_LESSTHAN = bytes([159])
OP_GREATERTHAN = bytes([160])
OP_LESSTHANOREQUAL = bytes([161])
OP_GREATERTHANOREQUAL = bytes([162])
OP_MIN = bytes([163])
OP_MAX = bytes([164])
OP_WITHIN = bytes([165])
OP_RIPEMD160 = bytes([166])
OP_SHA1 = bytes([167])
OP_SHA256 = bytes([168])
OP_HASH160 = bytes([169])
OP_HASH256 = bytes([170])
OP_CHECKSIG = bytes([172])
OP_CHECKSIGVERIFY = bytes([173])
OP_CHECKMULTISIG = bytes([174])
OP_CHECKMULTISIGVERIFY = bytes([175])
OP_CHECKLOCKTIMEVERIFY = bytes([177])
OP_CHECKSEQUENCEVERIFY = bytes([178])

OP_CODE_TO_NUMBER = {
    OP_0: 0,
    OP_1NEGATE: -1,
    OP_1: 1,
    OP_2: 2,
    OP_3: 3,
    OP_4: 4,
    OP_5: 5,
    OP_6: 6,
    OP_7: 7,
    OP_8: 8,
    OP_9: 9,
    OP_10: 10,
    OP_11: 11,
    OP_12: 12,
    OP_13: 13,
    OP_14: 14,
    OP_15: 15,
    OP_16: 16,
}

NUMBER_TO_OP_CODE = {v: k for k, v in OP_CODE_TO_NUMBER.items()}

OP_CODE_FUNCTIONS = {
    OP_0: op_0,
    OP_1: op_1,
    OP_2: op_2,
    OP_3: op_3,
    OP_4: op_4,
    OP_5: op_5,
    OP_6: op_6,
    OP_7: op_7,
    OP_8: op_8,
    OP_9: op_9,
    OP_10: op_10,
    OP_11: op_11,
    OP_12: op_12,
    OP_13: op_13,
    OP_14: op_14,
    OP_15: op_15,
    OP_16: op_16,
    OP_CHECKLOCKTIMEVERIFY: op_checklocktimeverify,
    OP_CHECKMULTISIG: op_checkmultisig,
    OP_CHECKMULTISIGVERIFY: op_checkmultisigverify,
    OP_CHECKSEQUENCEVERIFY: op_checksequenceverify,
    OP_CHECKSIG: op_checksig,
    OP_CHECKSIGVERIFY: op_checksigverify,
    OP_DROP: op_drop,
    OP_DUP: op_dup,
    OP_EQUAL: op_equal,
    OP_EQUALVERIFY: op_equalverify,
    OP_FROMALTSTACK: op_fromaltstack,
    OP_HASH160: op_hash160,
    OP_IF: op_if,
    OP_NOTIF: op_notif,
    OP_TOALTSTACK: op_toaltstack,
    OP_VERIFY: op_verify,
}

OP_CODE_NAMES = {
    OP_0: 'OP_0',
    OP_PUSHDATA1: 'OP_PUSHDATA1',
    OP_PUSHDATA2: 'OP_PUSHDATA2',
    OP_1NEGATE: 'OP_1NEGATE',
    OP_1: 'OP_1',
    OP_2: 'OP_2',
    OP_3: 'OP_3',
    OP_4: 'OP_4',
    OP_5: 'OP_5',
    OP_6: 'OP_6',
    OP_7: 'OP_7',
    OP_8: 'OP_8',
    OP_9: 'OP_9',
    OP_10: 'OP_10',
    OP_11: 'OP_11',
    OP_12: 'OP_12',
    OP_13: 'OP_13',
    OP_14: 'OP_14',
    OP_15: 'OP_15',
    OP_16: 'OP_16',
    OP_NOP: 'OP_NOP',
    OP_IF: 'OP_IF',
    OP_NOTIF: 'OP_NOTIF',
    OP_ELSE: 'OP_ELSE',
    OP_ENDIF: 'OP_ENDIF',
    OP_VERIFY: 'OP_VERIFY',
    OP_RETURN: 'OP_RETURN',
    OP_TOALTSTACK: 'OP_TOALTSTACK',
    OP_FROMALTSTACK: 'OP_FROMALTSTACK',
    OP_2DROP: 'OP_2DROP',
    OP_2DUP: 'OP_2DUP',
    OP_3DUP: 'OP_3DUP',
    OP_2OVER: 'OP_2OVER',
    OP_2ROT: 'OP_2ROT',
    OP_2SWAP: 'OP_2SWAP',
    OP_IFDUP: 'OP_IFDUP',
    OP_DEPTH: 'OP_DEPTH',
    OP_DROP: 'OP_DROP',
    OP_DUP: 'OP_DUP',
    OP_NIP: 'OP_NIP',
    OP_OVER: 'OP_OVER',
    OP_PICK: 'OP_PICK',
    OP_ROLL: 'OP_ROLL',
    OP_ROT: 'OP_ROT',
    OP_SWAP: 'OP_SWAP',
    OP_TUCK: 'OP_TUCK',
    OP_SIZE: 'OP_SIZE',
    OP_EQUAL: 'OP_EQUAL',
    OP_EQUALVERIFY: 'OP_EQUALVERIFY',
    OP_1ADD: 'OP_1ADD',
    OP_1SUB: 'OP_1SUB',
    OP_NEGATE: 'OP_NEGATE',
    OP_ABS: 'OP_ABS',
    OP_NOT: 'OP_NOT',
    OP_0NOTEQUAL: 'OP_0NOTEQUAL',
    OP_ADD: 'OP_ADD',
    OP_SUB: 'OP_SUB',
    OP_BOOLAND: 'OP_BOOLAND',
    OP_BOOLOR: 'OP_BOOLOR',
    OP_NUMEQUAL: 'OP_NUMEQUAL',
    OP_NUMEQUALVERIFY: 'OP_NUMEQUALVERIFY',
    OP_NUMNOTEQUAL: 'OP_NUMNOTEQUAL',
    OP_LESSTHAN: 'OP_LESSTHAN',
    OP_GREATERTHAN: 'OP_GREATERTHAN',
    OP_LESSTHANOREQUAL: 'OP_LESSTHANOREQUAL',
    OP_GREATERTHANOREQUAL: 'OP_GREATERTHANOREQUAL',
    OP_MIN: 'OP_MIN',
    OP_MAX: 'OP_MAX',
    OP_WITHIN: 'OP_WITHIN',
    OP_RIPEMD160: 'OP_RIPEMD160',
    OP_SHA1: 'OP_SHA1',
    OP_SHA256: 'OP_SHA256',
    OP_HASH160: 'OP_HASH160',
    OP_HASH256: 'OP_HASH256',
    OP_CHECKSIG: 'OP_CHECKSIG',
    OP_CHECKSIGVERIFY: 'OP_CHECKSIGVERIFY',
    OP_CHECKMULTISIG: 'OP_CHECKMULTISIG',
    OP_CHECKMULTISIGVERIFY: 'OP_CHECKMULTISIGVERIFY',
    OP_CHECKLOCKTIMEVERIFY: 'OP_CHECKLOCKTIMEVERIFY',
    OP_CHECKSEQUENCEVERIFY: 'OP_CHECKSEQUENCEVERIFY',
}
