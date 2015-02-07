
Quick'n dirty PoC for NoSuchCrackme Level 3

Writeup:  https://doar-e.github.io/presentations/securityday2015/Emilien%20Girault%20-%20SecurityDay2015%20-%20Solving%20NoSuchCrackme%20level%203.pdf

Usage: 

# Compile the payload
$ ./make.sh

# Perform the side-channel attack to recover the private exponent
$ ./poc.py <host> <payload>
  Example: ./poc.py nsc2014.synacktiv.com payload

# Decrypt the message with the private exponent
$ ./decrypt_msg.py 0x150627087e808aa34fc6b54bf1458adc211f4d176c50ad369ea4a7da66661929c427955402ccef89f31f4bcd54e00e8d698504b6693f775d588d378de88985748ef825428b507a6b5c48d42c1aa56cbbe801fbe3294b550d38f5f4ede5e567d00e33fd279ba29976934d6a2e0852c7e032666586e995bbf7d7255725fc0af162e81cbeb6bb74e01cfd0f46dd84dc78f75991be6a0b7e96765b1aee4b2ff115b7c7afc3af5fb3945ab88d3c989

Requires Metasploit (msfencode) and Elfesteem.
Please adapt the paths in msfencode_wrapper.sh to match your owns.

To decrypt the message

The securedrop contains the challenge files.

