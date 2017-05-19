#!/usr/bin/env python3

import random
import gmpy2
import sys

BITS = 4096

rand = random.Random(0xdeadbeef)

a1 = rand.getrandbits(BITS)
b1 = rand.getrandbits(BITS)
c1 = a1 * b1
a2 = rand.getrandbits(BITS)
b2 = rand.getrandbits(BITS)
c2 = a2 * b2

SZ = BITS // 8

# input data
with open(sys.argv[1], 'wb') as f:
    # A
    f.write(int(a1).to_bytes(SZ, 'little'))
    # B
    f.write(int(b1).to_bytes(SZ, 'little'))
    # A
    f.write(int(a2).to_bytes(SZ, 'little'))
    # B
    f.write(int(b2).to_bytes(SZ, 'little'))

# expected output
with open(sys.argv[2], 'w') as f:
    # C
    f.write(''.join('{:02X}'.format(x) for x in int(c1).to_bytes(SZ * 2, 'little')))
    f.write('\n')
    # C
    f.write(''.join('{:02X}'.format(x) for x in int(c2).to_bytes(SZ * 2, 'little')))
    f.write('\n')
