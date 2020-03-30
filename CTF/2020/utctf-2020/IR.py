#!/usr/bin/env python

# Is llvm IR
# Read some here https://llvm.org/docs/SourceLevelDebugging.html#object-lifetimes-and-scoping

import string

check = "\x03\x12\x1A\x17\x0A\xEC\xF2\x14\x0E\x05\x03\x1D\x19\x0E\x02\x0A\x1F\x07\x0C\x01\x17\x06\x0C\x0A\x19\x13\x0A\x16\x1C\x18\x08\x07\x1A\x03\x1D\x1C\x11\x0B\xF3\x87\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05"
check = [ ord(x) for x in check ]

def dso_local():
  flag="utflag{"
  flag=flag + ("X"*(64- len(flag) -1)) + "}"
  flag=[ord(x) for x in flag]
  start_from = 1
  for x in range(start_from, len(flag) - 1, 1):
    #print("[-] compare check[{0}]=0x{1:x} with prec={2}".format( x, check[x], chr(flag[x-1])) )
    prec = flag[x-1]
    for y in string.printable:
      if( ((prec + 5) % 256) ^ ((ord(y) + 5) % 256) == check[x-1]):
        flag[x]=ord(y)
  return flag

print("".join([chr(x) for x in dso_local() ]))

