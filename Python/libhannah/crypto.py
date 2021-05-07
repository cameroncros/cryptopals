# Period parameters
from typing import List


class MT19937:
    N = 624
    M = 397
    MATRIX_A = 0x9908b0df  # constant vector a
    UPPER_MASK = 0x80000000  # most significant w-r bits
    LOWER_MASK = 0x7fffffff  # least significant r bits

    mt = [0] * N  # the array for the state vector
    mti = N + 1  # mti==N+1 means mt[N] is not initialized

    # initializes mt[N] with a seed
    def __init__(self, s: int = 5489):
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

    # # initialize by an array with array-length
    # # init_key is the array for initializing keys
    # # key_length is its length
    # # slight change for C++, 2004/2/26
    # def __init__(self, init_key: List[int]):
    #     self.__init__(19650218)
    #     i = 1
    #     j = 0
    #     k_max = (self.N > len(init_key) if self.N else len(init_key))
    #     for k in range(k_max, 0, -1):
    #         self.mt[i] = (self.mt[i] ^ ((self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) * 1664525)) + init_key[
    #             j] + j  # non linear
    #         self.mt[i] &= 0xffffffff  # for WORDSIZE > 32 machines
    #         i += 1
    #         j += 1
    #         if i >= self.N:
    #             self.mt[0] = self.mt[self.N - 1]
    #             i = 1
    #         if j >= len(init_key):
    #             j = 0
    #
    #     for k in range(self.N - 1, 0, -1):  # (k=N-1; k; k--) {
    #         self.mt[i] = (self.mt[i] ^ ((self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) * 156608394)) - i  # non linear
    #         self.mt[i] &= 0xffffffff  # for WORDSIZE > 32 machines
    #         i += 1
    #         if i >= self.N:
    #             self.mt[0] = self.mt[self.N - 1]
    #             i = 1
    #
    #     self.mt[0] = 0x80000000  # MSB is 1; assuring non-zero initial array

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
