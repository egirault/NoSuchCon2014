from os import urandom
from ctypes import *
import socket

PASSWORD = "UBNtYTbYKWBeo12cHr33GHREdZYyOHMZ"

n = 0xd01a72efdbd988acb178f24c94110482d7575a27e1126cc693bfc219874ebe4d9cd691e7ccffbe126e169db31547db17dbe7573e98cc7bc249a3bfefeb40eb0210cec9db71fc1f8b5630f7a552eafb241a5d7cd0d5fdfdc44db2fb2497f094ae1a332f7b703c0813be79f581b59da0259556a265f7b70023cab86881b6c6803ccc66611f1da5e50c23ca434a339dca13ba95b4fdb7ea3cbe6e4b25d03001ac937c6a47f1133776cc8ed23870b
e = 0x10001
ks = (len('%x'%n) + 1) / 2

sec = cdll.LoadLibrary("libsec.so")
sec.SEC_init()

def ocb_crypt(key, msg) :
	enc = create_string_buffer(len(msg)+16+12)
	k = create_string_buffer(sec.SEC_sizeof_key())
	szout = c_int()
	assert sec.SEC_create_sym_key(k, key) == 0
	assert sec.SEC_encrypt(k, len(msg), msg, byref(szout), enc) == 0
	assert szout.value == len(msg)+16+12
	sec.SEC_free_key(k)
	return str(enc.raw)

def ocb_decrypt(key, msg) :
	assert len(msg) > 16+12
	dec = create_string_buffer(len(msg)-16-12)
	k = create_string_buffer(sec.SEC_sizeof_key())
	szout = c_int()
	assert sec.SEC_create_sym_key(k, key) == 0
	assert sec.SEC_decrypt(k, len(msg), msg, byref(szout), dec) == 0
	assert szout.value == len(msg)-16-12
	sec.SEC_free_key(k)
	return str(dec.raw)

def genpad(l) :
	p = ''
	for _ in xrange(l) :
		c = urandom(1)
		while c == '\x00' :
			c = urandom(1)
		p += c
	return p

print 'enter your message (ctrl+c so send it):'

m = ''
try :
	while 1 :
		m += raw_input() + '\n'
except KeyboardInterrupt :
	pass
assert len(m) < (10000-16-12)/2

k = urandom(16)
enc = ocb_crypt(k, m)
ocb_decrypt(k, enc)

wk = '\x00\x02' + genpad(ks-16-2-1) + '\x00' + k
wk = int(wk.encode('hex'), 16)
wk = pow(wk, e, n)
wk = '%0*X'%(ks*2, wk)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(15)
s.connect(('nsc2014.synacktiv.com', 1337))

s.send('%s\n%s\n%s\n'%(PASSWORD, wk, enc.encode('hex')))
r = ''
while '\n' not in r :
	r += s.recv(1024)

try :
	r = r.strip('\n').decode('hex')
	print ocb_decrypt(k, r)
except :
	print r
