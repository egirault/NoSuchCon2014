#!/bin/bash

# Metasploit-Encode wrapper
# Adapt to your own paths

source ~/.rvm/scripts/rvm 
cd ~/metasploit-framework/
ruby msfencode $*

