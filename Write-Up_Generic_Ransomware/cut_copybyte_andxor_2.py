#!/usr/bin/env python
# coding=utf-8
import sys,struct

def main(args):
 filez = open(args[0], "rb")
 output = open("output_{0}".format( args[0] ), "wb")
 key = list("".join( [ chr(int(x)) for x in "216, 37, 234, 75, 173, 181, 32, 27, 146, 14, 61, 8, 255, 62, 172, 235, 201, 198, 196, 81, 110, 116, 186, 4, 79, 56, 148, 95, 191, 209, 117, 169, 231, 2, 42".split(", ")] ))
 len_key = len(key)
 
 print("#payload")
 ret_raw = filez.read()
 out_raw = []
 for x in range(len(ret_raw)):
  v3,=struct.unpack("B", ret_raw[x])
  v3 ^= ord( key[x % len_key] )
  out_raw.append(struct.pack("B", v3))

 output.write("".join(out_raw))
 
 print(len(ret_raw))
 print(key)
 filez.close()
 output.close()


if __name__ == "__main__":
  main( sys.argv[1:] )
