#!/usr/bin/python

from libclient import *
import sys

encrypted_symkey = 0x0C849AFE0A7C11B2F083C32E7FDB0F8AC03198D84D9990B26D6443B1D185A36A235A561BB99FE897858371311B2AD6DFE75E199667637EDEA7B9C14A158A5F6FFE15A1C14DAD808FDC9F846530EDD4FE3E86F4F98571CD45F11190ED531FC940D62C2C2E05F99772235808097763157F140FE4A57DB6AD902D9962F12BDFC1547CED3E282604255B2A5331373CAEE557CC825DD6A03C3D2D7B106E4AD15347BCB5067BDC60376FF1CC133F2C14
encrypted_msg = "9d41dbb8da10b66cdde844f62e9cc4f96c3a88730b7b8307810cf1906935123f97ac9b682dd401512d18775bd7bd9b8b40929f5b4a1871ba44c94038793f0aa639b9d71d72d2accfcc95671c77a5c1c32bc813b048f5dcb1f08b59d6a7afb3b34462ac6abb69cb70accb24d78389a1777c5244b8063c542cc1f6c6db8d41d32df2e7132e21db8a1cc711c1a97c51ba29f1d1ac8fa901a902b2a987f0764734f8b8cd2d476200e7ae62a424e2930d8b029409d0e5e13d4e11f4b5f5cc1263f41b500b4340b8641465bbc56c64a575f0ee215d02dea3d75552328cf5742c".decode('hex')

d = int(sys.argv[1], 0)
# 0x150627087e808aa34fc6b54bf1458adc211f4d176c50ad369ea4a7da66661929c427955402ccef89f31f4bcd54e00e8d698504b6693f775d588d378de88985748ef825428b507a6b5c48d42c1aa56cbbe801fbe3294b550d38f5f4ede5e567d00e33fd279ba29976934d6a2e0852c7e032666586e995bbf7d7255725fc0af162e81cbeb6bb74e01cfd0f46dd84dc78f75991be6a0b7e96765b1aee4b2ff115b7c7afc3af5fb3945ab88d3c989

ks = 173

print "[+] Decrypting symmetric key"
decrypted_symkey = pow(encrypted_symkey, d, N)
decrypted_symkey = ("%0*X" % (ks*2, decrypted_symkey)).decode('hex')

print "[+] Checking padding"
assert decrypted_symkey[:2] == "\x00\x02"

print "[+] Skipping padding"
decrypted_symkey = decrypted_symkey[2:]
pad_len = ks-16-2-1
decrypted_symkey = decrypted_symkey[pad_len+1:] # skip null byte as well

print "[+] Decrypted symmetric key = %s" % (decrypted_symkey.encode('hex'))

print "[+] Decrypted message :\n"
msg = ocb_decrypt(decrypted_symkey, encrypted_msg)

print msg

