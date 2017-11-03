#!/usr/bin/python

from __future__ import division

import argparse
import threading
import time
import struct
import sys
from Crypto.Cipher import DES

decrypt_times = []

class myThread(threading.Thread):
   def __init__(self, name, begin, end):
      threading.Thread.__init__(self)
      self.name = name
      self.begin = begin
      self.end = end

   def run(self):

      #print "Starting " + self.name + "\nbegin: " + str(self.begin)
      key = self.begin
      #print "Thread started"
      while(key < self.end and (key < (1<<63))):
          #if(not valid_key(key)):
          #    continue
          keystr = struct.pack("<Q", key)
          #print "Packed"
          cipher = DES.new(keystr, DES.MODE_CBC, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00")
          if(cipher.decrypt(cipher_text)[8:-8] == plaintext):
              key += 1
              print cipher.decrypt(cipher_text)[8:-8]
              print struct.pack("<Q", key)
              print key
              sys.stdout.flush()
              print "Time, " + self.name + "\t" + str(time.time() - start_time)
              break
          key += 1
          #print "return"
      print "Exiting " + self.name

class cycle_thread(threading.Thread):
   def __init__(self, name, begin, end, cipher_text, plaintext, start_time):
      threading.Thread.__init__(self)
      self.name = name
      self.begin = begin
      self.end = end
      self.cipher_text = cipher_text
      self.plaintext = plaintext
      self.start_time = start_time

   def run(self):

        begin_keystr = self.begin
        end_keystr = self.end

        keystr = [c for c in begin_keystr]
        zeros = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        while keystr[0] <= end_keystr[0]:
            while keystr[1] <= end_keystr[1]:
                while keystr[2] <= end_keystr[2]:
                    while keystr[3] <= end_keystr[3]:
                        while keystr[4] <= end_keystr[4]:
                            while keystr[5] <= end_keystr[5]:
                                while keystr[6] <= end_keystr[6]:
                                    while keystr[7] <= end_keystr[7]:
                                        dec_begin = time.time()
                                        cipher = DES.new(''.join(keystr), DES.MODE_CBC, iv=zeros)

                                        if(cipher.decrypt(self.cipher_text)[8:-8] == self.plaintext):
                                            print cipher.decrypt(self.cipher_text)[8:-8]
                                            sys.stdout.flush()
                                            print "Threads Time\t" + str(time.time() - self.start_time)
                                            return
                                        if(keystr[7] == '\xFE'): break
                                        keystr[7] = chr(ord(keystr[7]) + 2)
                                    keystr[7] = begin_keystr[7]
                                    if(keystr[6] == '\xFE'): break
                                    keystr[6] = chr(ord(keystr[6]) + 2)
                                keystr[6] = begin_keystr[6]
                                if(keystr[5] == '\xFE'): break
                                keystr[5] = chr(ord(keystr[5]) + 2)
                            keystr[5] = begin_keystr[5]
                            if(keystr[4] == '\xFE'): break
                            keystr[4] = chr(ord(keystr[4]) + 2)
                        keystr[4] = begin_keystr[4]
                        if(keystr[3] == '\xFE'): break
                        keystr[3] = chr(ord(keystr[3]) + 2)
                    keystr[3] = begin_keystr[3]
                    if(keystr[2] == '\xFE'): break
                    keystr[2] = chr(ord(keystr[2]) + 2)
                keystr[2] = begin_keystr[2]
                if(keystr[1] == '\xFE'): break
                keystr[1] = chr(ord(keystr[1]) + 2)
            keystr[1] = begin_keystr[1]
            if(keystr[0] == '\xFE'): break
            keystr[0] = chr(ord(keystr[0]) + 2)

        print "Exiting " + self.name
        return

def valid_key(key):
    #print "in valid_key"
    for i in range(8):
        ones = 0
        key_byte = key & (0b11111111 << i)
        print key_byte
        while(key_byte != 0):
            if((key_byte & 1) == 1):
                ones +=1
            key_byte = key_byte >> 1
        if(ones%2 != 0):
            return False
    return True

def try_key_range(start, stop):
    key = start
    #print "Thread started"
    while(key < stop and (key < (1<<63))):
        if(not valid_key(key)):
            continue
        keystr = struct.pack("<Q", key)
        #print "Packed"
        cipher = DES.new(keystr, DES.MODE_CBC, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00")
        if(cipher.decrypt(cipher_text)[8:-8] == plaintext):
            key += 1
            print cipher.decrypt(cipher_text)[8:-8]
            print struct.pack("<Q", key)
            print key
            sys.stdout.flush()
            print "Sequential Time\t" + str(time.time() - start_time)
            break
        key += 1
        #print "return"

def try_key_range_bytes(begin_keystr, end_keystr, cipher_text, plaintext, start_time):

    keystr = [c for c in begin_keystr]
    print "Fixed key: " + ''.join(keystr)
    zeros = b"\x00\x00\x00\x00\x00\x00\x00\x00"

    while keystr[0] <= end_keystr[0]:
        while keystr[1] <= end_keystr[1]:
            while keystr[2] <= end_keystr[2]:
                while keystr[3] <= end_keystr[3]:
                    while keystr[4] <= end_keystr[4]:
                        while keystr[5] <= end_keystr[5]:
                            while keystr[6] <= end_keystr[6]:
                                while keystr[7] <= end_keystr[7]:
                                    dec_begin = time.time()
                                    cipher = DES.new(''.join(keystr), DES.MODE_CBC, iv=zeros)
                                    dec_end = time.time()
                                    decrypt_times.append(dec_end - dec_begin)
                                    if(cipher.decrypt(cipher_text)[8:-8] == plaintext):
                                        print cipher.decrypt(cipher_text)[8:-8]
                                        sys.stdout.flush()
                                        print "Sequential Time\t" + str(time.time() - start_time)
                                        return
                                    if(keystr[7] >= '\xFE'): break
                                    keystr[7] = chr(ord(keystr[7]) + 2)
                                keystr[7] = begin_keystr[7]
                                if(keystr[6] >= '\xFE'): break
                                keystr[6] = chr(ord(keystr[6]) + 2)
                            keystr[6] = begin_keystr[6]
                            if(keystr[5] >= '\xFE' ): break
                            keystr[5] = chr(ord(keystr[5]) + 2)
                        keystr[5] = begin_keystr[5]
                        if(keystr[4] >= '\xFE' ): break
                        keystr[4] = chr(ord(keystr[4]) + 2)
                    keystr[4] = begin_keystr[4]
                    if(keystr[3] >= '\xFE' ): break
                    keystr[3] = chr(ord(keystr[3]) + 2)
                keystr[3] = begin_keystr[3]
                if(keystr[2] >= '\xFE' ): break
                keystr[2] = chr(ord(keystr[2]) + 2)
            keystr[2] = begin_keystr[2]
            if(keystr[1] >= '\xFE'): break
            keystr[1] = chr(ord(keystr[1]) + 2)
        keystr[1] = begin_keystr[1]
        if(keystr[0] >= '\xFE'): break
        keystr[0] = chr(ord(keystr[0]) + 2)
    return



def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--multithread", metavar="NUM_THREADS", type=int, help="Use multithread")
    args = parser.parse_args()
    num_threads = args.multithread

    key = [b'-8B key-',b'fwerbw4t',b'1431344y',b'g34g4g4y',b'esr-sf--',b'+wwf+ww5',b'fww36yy.',b'.q34.34f']

    for i in range(len(key)):
        print "\nDecryption with key:\t" + key[i]
        f = open("cipher_text"+str(i)+".txt", "r")
        ff = open("chosen_plaintext"+str(i)+".txt", "r")

        cipher_text = f.read().strip()
        plaintext = ff.readlines()
        ptxt_len = int(plaintext[1])

        plaintext = plaintext[0][:ptxt_len]

        max_key = 18302063728033398269

        start_time = time.time()

        start_key_str = key[i][0:6] + b"\x00\x00"
        end_key_str = key[i][0:6] + b"\xFF\xFF"

        start_key = struct.unpack("<Q", start_key_str)[0]
        end_key = struct.unpack("<Q", end_key_str)[0]

        key_range = end_key - start_key

        if(num_threads):
            for i in range(num_threads):
                begin = start_key + i*(key_range//num_threads)
                end  = (start_key + (i+1)*(key_range//num_threads))
                #print begin, end
                thread = cycle_thread("Thread-"+str(i), struct.pack("<Q", begin), struct.pack("<Q", end), cipher_text, plaintext, start_time)
                thread.start()

        else:
            try_key_range_bytes(start_key_str, end_key_str, cipher_text, plaintext, start_time)

        f.close()

    a = 0
    for e in decrypt_times:
        a += e
    if(len(decrypt_times)>0):
        print "Average decyption time: " + str(a/len(decrypt_times))

if __name__ == '__main__':
    main()
