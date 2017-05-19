#!/usr/bin/env python3

import sys

open(sys.argv[1], 'w').close()
with open(sys.argv[2], 'w') as f:
    f.write('00' * 0x1000)
    f.write('\n')


