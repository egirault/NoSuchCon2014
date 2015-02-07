#!/usr/bin/python2
# -*- coding: utf-8 -*-

from subprocess import *
import os

BASH = "/bin/bash"
MSFENCODE_WRAPPER = "./msfencode_wrapper.sh"

ENCODER = "x64/xor"  # "x86/shikata_ga_nai"
BAD_CHARS = "\\x0a" # "\\x00\\xff\\x0a\\x0d"

def extract_text(filename):
    """Extrait la section .text d'un ELF"""
    from elfesteem import elf_init
    e = elf_init.ELF(open(filename, "rb").read())
    s = e.getsectionbyname('.text')
    return str(s.content)

def msfencode(shellcode):
    p = Popen([BASH, MSFENCODE_WRAPPER, "-e", ENCODER, "-t", "raw", "-b", BAD_CHARS], 
        stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout = p.communicate(input=shellcode)[0]
    return stdout

def extract_text_and_encode(filename):
    shellcode = extract_text(filename)
    return msfencode(shellcode)

