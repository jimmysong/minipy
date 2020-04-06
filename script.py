from __future__ import annotations

from io import BufferedIOBase, BytesIO
from typing import List, Optional

from helper import (
    byte_to_int,
    encode_varstr,
    hash160,
    int_to_byte,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    sha256,
)
from op import (
    decode_num,
    encode_minimal_num,
    is_number_op_code,
    number_to_op_code,
    op_code_to_number,
    OP_0,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKMULTISIGVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
    OP_DROP,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_FROMALTSTACK,
    OP_HASH160,
    OP_IF,
    OP_NOTIF,
    OP_PUSHDATA1,
    OP_PUSHDATA2,
    OP_TOALTSTACK,
    OP_VERIFY,
    OP_CODE_NAMES,
    OP_CODE_FUNCTIONS,
)
from timelock import Locktime, Sequence
from witness import Witness


class Script(list):
    def __add__(self, other: Script) -> Script:
        return Script(super().__add__(other))

    def __new__(cls,
                commands: Optional[List[Union(bytes, str)]] = None) -> Script:
        if commands is None:
            commands = []
        for current in commands:
            if type(current) not in (bytes, ):
                raise ValueError(
                    f'Every command should be bytes or str, got {current} instead'
                )
        return super().__new__(cls, commands)

    def __repr__(self) -> str:
        result = ''
        for current in self:
            if OP_CODE_NAMES.get(current):
                result += f'{OP_CODE_NAMES.get(current)} '
            elif type(current) == str:
                result += f'<{current}> '
            else:
                result += f'{current.hex()} '
        return result

    @classmethod
    def parse(cls, s: BufferedIOBase) -> Script:
        # get the length of the entire field
        length = read_varint(s)
        # initialize the commands array
        commands = []
        # initialize the number of bytes we've read to 0
        count = 0
        # loop until we've read length bytes
        while count < length:
            # get the current byte
            current = s.read(1)
            # increment the bytes we've read
            count += 1
            # convert the current byte to an integer
            current_int = current[0]
            # if the current byte is between 1 and 75 inclusive
            if current_int <= 75:
                # add the next n bytes as a command
                commands.append(s.read(current_int))
                count += current_int
            elif current == OP_PUSHDATA1:
                # op_pushdata1
                data_length = byte_to_int(s.read(1))
                commands.append(s.read(data_length))
                count += data_length + 1
            elif current == OP_PUSHDATA2:
                # op_pushdata2
                data_length = little_endian_to_int(s.read(2))
                commands.append(s.read(data_length))
                count += data_length + 2
            else:
                # add the command to the list of commands
                commands.append(current)
        if count != length:
            raise SyntaxError(f'parsing script failed {commands}')
        return cls(commands)

    def miniscript(self):
        from miniscript import MiniScript
        return MiniScript.from_script(Script(self[:]))

    def is_locktime_locked(self) -> bool:
        '''Returns whether the script starts with
        <locktime> OP_CLTV OP_DROP'''
        return len(self) >= 3 and \
            (is_number_op_code(self[0]) or len(self[0]) > 1) and \
            self[1] == OP_CHECKLOCKTIMEVERIFY and self[2] == OP_DROP

    def is_multisig(self) -> bool:
        '''Returns whether the script follows the
        OP_k <pubkey1>...<pubkeyn> OP_n OP_CHECKMULTISIG pattern'''
        if self[-1] != OP_CHECKMULTISIG:
            return False
        if not is_number_op_code(self[-2]):
            return False
        n = op_code_to_number(self[-2])
        if len(self) < n + 3:
            return False
        for current in self[-n - 2:-2]:
            if len(current) != 33:
                return False
        if not is_number_op_code(self[-n - 3]):
            return False
        k = op_code_to_number(self[-n - 3])
        if k < 1 or k > 15:
            return False
        if n < k or n > 15:
            return False
        return True

    def is_multisig_timelock(self) -> bool:
        '''Returns whether the script follows the
        <locktime> OP_CLTV/OP_CSV OP_DROP OP_k <pubkey1>...<pubkeyn> OP_n OP_CHECKMULTISIG pattern'''
        return (self.is_sequence_locked() or self.is_locktime_locked()) and \
            self.is_multisig()

    def is_p2pkh(self) -> bool:
        '''Returns whether the script follows the
        OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG pattern.'''
        # there should be exactly 5 commands
        # OP_DUP, OP_HASH160, 20-byte hash, OP_EQUALVERIFY, OP_CHECKSIG
        return len(self) == 5 and self[0] == OP_DUP and self[1] == OP_HASH160 \
            and len(self[2]) == 20 and self[3] == OP_EQUALVERIFY \
            and self[4] == OP_CHECKSIG

    def is_p2sh(self) -> bool:
        '''Returns whether the script follows the
        OP_HASH160 <20 byte hash> OP_EQUAL pattern.'''
        # there should be exactly 3 commands
        # OP_HASH160, 20-byte hash, OP_EQUAL
        return len(self) == 3 and self[0] == OP_HASH160 and len(self[1]) == 20 \
            and self[2] == OP_EQUAL

    def is_p2wpkh(self) -> bool:
        '''Returns whether the script follows the
        OP_0 <20 byte hash> pattern.'''
        return len(self) == 2 and self[0] == OP_0 and len(self[1]) == 20

    def is_p2wsh(self) -> bool:
        '''Returns whether the script follows the
        OP_0 <32 byte hash> pattern.'''
        return len(self) == 2 and self[0] == OP_0 and len(self[1]) == 32

    def is_segwit(self) -> bool:
        return self.is_p2wpkh() or self.is_p2wsh()

    def is_sequence_locked(self) -> bool:
        '''Returns whether the script starts with
        <sequence> OP_CSV OP_DROP'''
        return len(self) >= 3 and \
            (is_number_op_code(self[0]) or len(self[0]) > 1) and \
            self[1] == OP_CHECKSEQUENCEVERIFY and self[2] == OP_DROP

    def is_timelock(self) -> bool:
        '''Returns whether the script follows the
        locktime OP_CLTV OP_DROP <pubkey> OP_CHECKSIG pattern'''
        return (self.is_sequence_locked() or self.is_locktime_locked()) and \
            len(self) == 5 and len(self[3]) == 33 and self[4] == OP_CHECKSIG

    def pubkeys(self) -> List[bytes]:
        pubkeys = []
        for item in self:
            if len(item) == 33 and item[0] in (2, 3):
                pubkeys.append(item)
        return pubkeys

    def raw_serialize(self) -> bytes:
        # initialize what we'll send back
        result = b''
        # go through each command
        for current in self:
            if current == OP_0:
                result += int_to_byte(0)
            elif OP_CODE_NAMES.get(current) is None:
                # this is an element
                # get the length in bytes
                length = len(current)
                # for large lengths, we have to use a pushdata op code
                if length < 75:
                    # turn the length into a single byte integer
                    result += int_to_byte(length)
                elif length > 75 and length < 0x100:
                    # 76 is pushdata1
                    result += OP_PUSHDATA1
                    result += int_to_byte(length)
                elif length >= 0x100 and length <= 520:
                    # 77 is pushdata2
                    result += OP_PUSHDATA2
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long a command')
            result += current
        return result

    def serialize(self) -> bytes:
        return encode_varstr(self.raw_serialize())


class ScriptPubKey(Script):
    '''Represents a ScriptPubKey in a transaction'''
    @classmethod
    def parse(cls, s: BufferedIOBase) -> ScriptPubKey:
        script_pubkey = super().parse(s)
        if script_pubkey.is_p2pkh():
            return PKHScriptPubKey.from_hash(script_pubkey[2])
        elif script_pubkey.is_p2sh():
            return SHScriptPubKey.from_hash(script_pubkey[1])
        elif script_pubkey.is_p2wpkh():
            return WPKHScriptPubKey.from_hash(script_pubkey[1])
        elif script_pubkey.is_p2wsh():
            return WSHScriptPubKey.from_hash(script_pubkey[1])
        else:
            return script_pubkey

    def redeem_script(self) -> RedeemScript:
        '''Convert this ScriptPubKey to its RedeemScript equivalent'''
        return RedeemScript(self)


class PKHScriptPubKey(ScriptPubKey):
    @classmethod
    def from_hash(cls, h160: bytes) -> PKHScriptPubKey:
        if len(h160) != 20:
            raise TypeError('h160 should be 20 bytes')
        return cls([OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY, OP_CHECKSIG])

    def hash160(self) -> bytes:
        return self[2]


class SHScriptPubKey(ScriptPubKey):
    @classmethod
    def from_hash(cls, h160: bytes) -> SHScriptPubKey:
        if len(h160) != 20:
            raise TypeError('h160 should be 20 bytes')
        return cls([OP_HASH160, h160, OP_EQUAL])

    def hash160(self) -> bytes:
        return self[1]


class RedeemScript(Script):
    '''Subclass that represents a RedeemScript for p2sh'''
    def hash160(self) -> bytes:
        '''Returns the hash160 of the serialization of the RedeemScript'''
        return hash160(self.raw_serialize())

    def script_pubkey(self) -> SHScriptPubKey:
        '''Returns the ScriptPubKey that this RedeemScript corresponds to'''
        return SHScriptPubKey.from_hash(self.hash160())


class SegwitPubKey(ScriptPubKey):
    def hash(self) -> bytes:
        return self[1]


class WPKHScriptPubKey(SegwitPubKey):
    @classmethod
    def from_hash(cls, h160: bytes) -> WPKHScriptPubKey:
        if len(h160) != 20:
            raise TypeError('h160 should be 20 bytes')
        return cls([OP_0, h160])


class WSHScriptPubKey(SegwitPubKey):
    @classmethod
    def from_hash(cls, s256: bytes) -> WSHScriptPubKey:
        if len(s256) != 32:
            raise TypeError('s256 should be 32 bytes')
        return cls([OP_0, s256])


class WitnessScript(Script):
    '''Subclass that represents a WitnessScript for p2wsh'''
    def redeem_script(self) -> RedeemScript:
        return self.script_pubkey().redeem_script()

    def script_pubkey(self) -> WSHScriptPubKey:
        '''Generates the ScriptPubKey for p2wsh'''
        # get the sha256 of the current script
        # return new p2wsh script using p2wsh_script
        return WSHScriptPubKey.from_hash(self.sha256())

    def sha256(self) -> bytes:
        '''Returns the sha256 of the raw serialization for witness program'''
        return sha256(self.raw_serialize())


class MultiSigScript(Script):
    @classmethod
    def from_pubkeys(cls, k: int, sec_pubkeys: List[bytes]) -> MultiSigScript:
        n = len(sec_pubkeys)
        if k == 0 or k > n:
            raise ValueError(f'cannot do {k} of {n} keys')
        return cls([
            number_to_op_code(k), *sorted(sec_pubkeys),
            number_to_op_code(n), OP_CHECKMULTISIG
        ])


class MultiSigRedeemScript(RedeemScript, MultiSigScript):
    pass


class MultiSigWitnessScript(WitnessScript, MultiSigScript):
    pass


class TimelockScript(Script):
    @classmethod
    def from_time(cls,
                  locktime: Optional[Locktime] = None,
                  sequence: Optional[Sequence] = None) -> List[bytes]:
        if locktime is not None:
            return [
                encode_minimal_num(locktime), OP_CHECKLOCKTIMEVERIFY, OP_DROP
            ]
        elif sequence is not None:
            return [
                encode_minimal_num(sequence), OP_CHECKSEQUENCEVERIFY, OP_DROP
            ]
        else:
            raise ValueError('locktime or sequence required')


class SingleSigTimelockScript(TimelockScript):
    @classmethod
    def from_pubkey_time(
            cls,
            sec: bytes,
            locktime: Optional[Locktime] = None,
            sequence: Optional[Sequence] = None) -> SingleSigTimelockScript:
        script = cls.from_time(locktime, sequence) + [sec, OP_CHECKSIG]
        return cls(script)


class SingleSigTimelockRedeemScript(RedeemScript, SingleSigTimelockScript):
    pass


class SingleSigTimelockWitnessScript(WitnessScript, SingleSigTimelockScript):
    pass


class MultiSigTimelockScript(TimelockScript, MultiSigScript):
    @classmethod
    def from_pubkeys_time(
            cls,
            k: int,
            sec_pubkeys: List[bytes],
            locktime: Optional[Locktime] = None,
            sequence: Optional[Sequence] = None) -> MultiSigTimelockScript:
        script = cls.from_time(locktime, sequence) + cls.from_pubkeys(
            k, sec_pubkeys)
        return cls(script)


class MultiSigTimelockRedeemScript(RedeemScript, MultiSigTimelockScript):
    pass


class MultiSigTimelockWitnessScript(WitnessScript, MultiSigTimelockScript):
    pass
