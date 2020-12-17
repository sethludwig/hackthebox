import hashlib,binascii
import sys
import socket
import time
import struct
import subprocess
import passlib.hash;

string = sys.argv[1]

print "LM Hash:"+passlib.hash.lmhash.encrypt(string)
print "NT Hash:"+passlib.hash.nthash.encrypt(string)
