#!/usr/bin/python

import sys
import struct
from Crypto.Cipher import DES
from Crypto.Util import Padding


key = [b'-8B key-',b'fwerbw4t',b'1431344y',b'g34g4g4y',b'esr-sf--',b'+wwf+ww5',b'fww36yy.',b'.q34.34f']



message = b'messagge for you'
plaintext = Padding.pad(message, 8)

for i in range(len(key)):

    ff = open("chosen_plaintext"+str(i)+".txt", "w")

    ff.write(plaintext)
    ff.write("\n")
    ff.write(str(len(message)))

    cipher = DES.new(key[i], DES.MODE_CBC, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00")
    msg = cipher.iv + cipher.encrypt(plaintext)

    print hex(struct.unpack("<L", cipher.iv[:4])[0])

    f = open("cipher_text"+str(i)+".txt", "w")

    f.write(msg)

    f.close()
    ff.close()
