#!/usr/bin/env python
# coding=utf-8
import sys,struct

def main(args):
 filez = open(args[0], "rb")
 output = open("output_{0}".format( args[0] ), "wb")
 offset = int(args[1])
 till = int(args[2])
 key = list( "\xc6\x00\xc8\x00\x21\x00\x60\x00\x7e\x00\x24\x00\x2d\x00\x2e\x00\x2b\x00\x3d\x00" )
 len_key = len(key)
 
 #print("#header") 
 #ret_raw = filez.read(offset)
 #output.write(ret_raw)

 print("#payload")
 filez.seek(offset)
 ret_raw = filez.read(till)
 out_raw = []
 for x in range(len(ret_raw)):
  v3,=struct.unpack("B", ret_raw[x])
  v3 ^= ord( key[x % len_key] )
  out_raw.append(struct.pack("B", v3))

 output.write("".join(out_raw))

 #print("#tail")
 #filez.seek(offset + till)
 #ret_raw = filez.read()
 #output.write(ret_raw)
 
 print(len(ret_raw))
 filez.close()
 output.close()


if __name__ == "__main__":
  main( sys.argv[1:] )
