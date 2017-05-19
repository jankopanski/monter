#!/usr/bin/env python3

import random
import gmpy2
import sys

BITS = 2048

rand = random.Random(hash('test-multi-context'))

def get_numbers(bits, f_in):
    while True:
        n = gmpy2.next_prime(1 << (bits - 1) | rand.getrandbits(bits - 1))
        if n < (1 << bits):
            break
    np = gmpy2.invert(n & 0xffffffff, 1 << 32)
    r = 1 << bits
    rr = r * r % n

    a = rand.getrandbits(bits) % n
    b = rand.getrandbits(bits) % n
    c = a * (b ** 32) % n

    sz = bits // 8

    ### input data

    # A
    f_in.write(int(a).to_bytes(sz, 'little'))
    # buffer for intermediate results
    f_in.write(b'\xcc' * sz * 2)
    # B
    f_in.write(int(b).to_bytes(sz, 'little'))
    # N
    f_in.write(int(n).to_bytes(sz, 'little'))
    # RR
    f_in.write(int(rr).to_bytes(sz, 'little'))
    # N'
    f_in.write(int(np).to_bytes(4, 'little'))
    f_in.write(b'\x00' * (sz - 4))
    # 1
    f_in.write(int(1).to_bytes(sz, 'little'))

    ### expected output
    return ''.join('{:02X}'.format(x) for x in int(c).to_bytes(sz, 'little'))

with open(sys.argv[1], 'wb') as f_in:
    out1 = get_numbers(BITS, f_in)
    out2 = get_numbers(BITS*2, f_in)

with open(sys.argv[2], 'w') as f_out:
    f_out.write(out2 + '\n')
    f_out.write(out1 + '\n')
