# Period parameters
from typing import List

from z3.z3 import *

from libhannah.xor import xor


class MT19937:
    N = 624
    M = 397
    MATRIX_A = 0x9908b0df  # constant vector a
    UPPER_MASK = 0x80000000  # most significant w-r bits
    LOWER_MASK = 0x7fffffff  # least significant r bits

    # initializes mt[N] with a seed
    def __init__(self, s: int = 5489):
        self.mt: List[int] = [0] * self.N  # the array for the state vector
        self.mti: int = self.N + 1  # mti==N+1 means mt[N] is not initialized
        self.mt[0] = s & 0xffffffff
        for i in range(1, self.N):  # (mti=1; mti<N; mti++)
            self.mti = i
            self.mt[self.mti] = (1812433253 * (self.mt[self.mti - 1] ^ (self.mt[self.mti - 1] >> 30)) + self.mti)
            # See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier.
            # In the previous versions, MSBs of the seed affect
            # only MSBs of the array mt[].
            # 2002/01/09 modified by Makoto Matsumoto
            self.mt[self.mti] &= 0xffffffff
            # for >32 bit machines
            # print("mt[%i] = 0x%x" % (self.mti, self.mt[self.mti]))
        self.mti = self.N + 1

    # generates a random number on [0,0xffffffff]-interval
    def genrand_int32(self) -> int:
        mag01 = [0x0, self.MATRIX_A]
        # mag01[x] = x * MATRIX_A  for x=0,1

        if self.mti >= self.N:  # generate N words at one time
            for kk in range(0, self.N - self.M):  # (kk=0;kk<N-M;kk++) {
                y = (self.mt[kk] & self.UPPER_MASK) | (self.mt[kk + 1] & self.LOWER_MASK)
                self.mt[kk] = self.mt[kk + self.M] ^ (y >> 1) ^ mag01[y & 0x1]
                # print("mt[%i] = 0x%x" % (kk, self.mt[kk]))

            for kk in range(self.N - self.M, self.N - 1):  # (;kk<N-1;kk++) {
                y = (self.mt[kk] & self.UPPER_MASK) | (self.mt[kk + 1] & self.LOWER_MASK)
                self.mt[kk] = self.mt[kk + (self.M - self.N)] ^ (y >> 1) ^ mag01[y & 0x1]
                # print("mt[%i] = 0x%x" % (kk, self.mt[kk]))

            y = (self.mt[self.N - 1] & self.UPPER_MASK) | (self.mt[0] & self.LOWER_MASK)
            self.mt[self.N - 1] = self.mt[self.M - 1] ^ (y >> 1) ^ mag01[y & 0x1]
            # print("mt[N-1] = 0x%x" % (self.mt[self.N-1]))
            self.mti = 0

        y = self.mt[self.mti]
        self.mti += 1
        # Tempering
        y ^= (y >> 11)
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= (y >> 18)

        return y

    # generates a random number on [0,0x7fffffff]-interval
    def genrand_int31(self) -> int:
        return self.genrand_int32() >> 1

    # generates a random number on [0,1]-real-interval
    def genrand_real1(self) -> float:
        return self.genrand_int32() * (1.0 / 4294967295.0)
        # divided by 2^32-1

    # generates a random number on [0,1)-real-interval
    def genrand_real2(self) -> float:
        return self.genrand_int32() * (1.0 / 4294967296.0)

    # generates a random number on (0,1)-real-interval
    def genrand_real3(self) -> float:
        return (self.genrand_int32() + 0.5) * (1.0 / 4294967296.0)
        # divided by 2^32

    # generates a random number on [0,1) with 53-bit resolution
    def genrand_res53(self) -> float:
        a = self.genrand_int32() >> 5
        b = self.genrand_int32() >> 6
        return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0)


def untemper_MT19937(y_start: int) -> int:
    # y = state
    # y = y ^  (y >> 11)
    # y = y ^ ((y <<  7) & 0x9D2C5680))
    # y = y ^ ((y << 15) & 0xEFC60000))
    # y = y ^  (y >> 18)
    # return y
    y1 = BitVec('y1', 32)
    y2 = BitVec('y2', 32)
    y3 = BitVec('y3', 32)
    y4 = BitVec('y4', 32)
    y = BitVecVal(y_start, 32)
    s = Solver()

    equations = [
        y2 == y1 ^ (LShR(y1, 11)),
        y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
        y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
        y == y4 ^ (LShR(y4, 18))
    ]
    s.add(equations)
    s.check()
    return s.model()[y1].as_long()


def enc_MT19937(buffer: bytes, key: bytes) -> bytes:
    assert (len(key) == 2)
    key_int = int.from_bytes(bytes=key, byteorder='little')
    keystream = b''
    rando = MT19937(key_int)
    while len(keystream) < len(buffer):
        keystream += rando.genrand_int32().to_bytes(byteorder='little', length=4)

    return xor(buffer, keystream)


def dec_MT19937(buffer: bytes, key: bytes) -> bytes:
    return enc_MT19937(buffer, key)