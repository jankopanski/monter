#!/usr/bin/env python3

import random
import gmpy2
import sys

BITS = 4096

rand = random.Random(1337)

while True:
    n = gmpy2.next_prime(1 << (BITS - 1) | rand.getrandbits(BITS - 1))
    if n < (1 << BITS):
        break
np = gmpy2.invert(n & 0xffffffff, 1 << 32)
r = 1 << BITS
rr = r * r % n

a = rand.getrandbits(BITS) % n
b = rand.getrandbits(BITS) % n
c = a * b % n

SZ = BITS // 8

# input data
with open(sys.argv[1], 'wb') as f:
    # buffer for intermediate results
    f.write(b'\xcc' * SZ * 2)
    # A
    f.write(int(a).to_bytes(SZ, 'little'))
    # B
    f.write(int(b).to_bytes(SZ, 'little'))
    # N
    f.write(int(n).to_bytes(SZ, 'little'))
    # RR
    f.write(int(rr).to_bytes(SZ, 'little'))
    # N'
    f.write(int(np).to_bytes(4, 'little'))
    f.write(b'\x00' * (SZ - 4))
    # 1
    f.write(int(1).to_bytes(SZ, 'little'))

# expected output
with open(sys.argv[2], 'w') as f:
    # C
    f.write(''.join('{:02X}'.format(x) for x in int(c).to_bytes(SZ, 'little')))
    f.write('\n')
