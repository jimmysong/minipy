from __future__ import annotations

from io import BufferedIOBase
from typing import Optional

from helper import (
    int_to_little_endian,
    little_endian_to_int,
)

MAX = (1 << 32) - 1
BLOCK_LIMIT = 500000000
SEQUENCE_DISABLE_RELATIVE_FLAG = 1 << 31
SEQUENCE_RELATIVE_TIME_FLAG = 1 << 22
SEQUENCE_MASK = (1 << 16) - 1


class Locktime(int):
    def __new__(cls, n: Optional[int] = None) -> Locktime:
        if n is None:
            n = 0
        if n < 0 or n > MAX:
            raise ValueError(f'Locktime must be between 0 and 2^32 - 1: {n}')
        return super().__new__(cls, n)

    @classmethod
    def parse(cls, s: BufferedIOBase) -> Locktime:
        return cls(little_endian_to_int(s.read(4)))

    def serialize(self) -> bytes:
        return int_to_little_endian(self, 4)

    def block_height(self) -> Optional[Locktime]:
        if self < BLOCK_LIMIT:
            return self
        else:
            return None

    def mtp(self) -> Optional[Locktime]:
        if self >= BLOCK_LIMIT:
            return self
        else:
            return None

    def comparable(self, other: Locktime) -> bool:
        return (self < BLOCK_LIMIT
                and other < BLOCK_LIMIT) or (self >= BLOCK_LIMIT
                                             and other >= BLOCK_LIMIT)

    def less_than(self, other: Locktime) -> bool:
        if self.comparable(other):
            return self < other
        else:
            raise ValueError(
                'locktimes where one is a block height and the other a unix time cannot be compared'
            )


class Sequence(int):
    def __new__(cls, n: Optional[int] = None) -> Sequence:
        if n is None:
            n = MAX
        if n < 0 or n > MAX:
            raise ValueError(f'Sequence must be between 0 and 2^32 - 1: {n}')
        return super().__new__(cls, n)

    @classmethod
    def parse(cls, s: BufferedIOBase) -> Sequence:
        return cls(little_endian_to_int(s.read(4)))

    @classmethod
    def from_relative_time(cls, num_seconds: int) -> Sequence:
        return cls(SEQUENCE_RELATIVE_TIME_FLAG | (num_seconds // 512))

    @classmethod
    def from_relative_blocks(cls, num_blocks: int) -> Sequence:
        return cls(num_blocks)

    def serialize(self) -> bytes:
        return int_to_little_endian(self, 4)

    def is_max(self) -> bool:
        return self == MAX

    def relative(self) -> bool:
        return self & SEQUENCE_DISABLE_RELATIVE_FLAG == 0

    def relative_blocks(self) -> Optional[int]:
        '''Returns the number of blocks that need to age'''
        if not self.relative():
            return None
        elif self & SEQUENCE_RELATIVE_TIME_FLAG:
            return None
        else:
            return self & SEQUENCE_MASK

    def relative_time(self) -> Optional[int]:
        '''Returns the number of seconds that need to age'''
        if not self.relative():
            return None
        elif self & SEQUENCE_RELATIVE_TIME_FLAG:
            return (self & SEQUENCE_MASK) << 9
        else:
            return None

    def comparable(self, other: Sequence) -> bool:
        if not self.relative() or not other.relative():
            return False
        return (self ^ other
                ) & SEQUENCE_RELATIVE_TIME_FLAG != SEQUENCE_RELATIVE_TIME_FLAG

    def less_than(self, other: Sequence) -> bool:
        if self.comparable(other):
            return self & SEQUENCE_MASK < other & SEQUENCE_MASK
        else:
            raise ValueError(
                'sequences where one is a relative block height and the other a relative unix time cannot be compared'
            )
