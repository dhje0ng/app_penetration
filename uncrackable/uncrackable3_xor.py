#!/usr/bin/python3

import binascii

xor = "pizzapizzapizzapizzapizz"
hexserial = "1d0811130f1749150d0003195a1d1315080e5a0017081314"
dehex = bytes.fromhex(hexserial).decode('utf-8')

def runxor(a, b):
    return "".join(chr(ord(a1) ^ ord(b1)) for a1, b1 in zip(a, b))

if __name__ == "__main__":
    secretkey = runxor(xor, dehex)
    print(secretkey)