#!/usr/bin/env python
import string

sub = lambda x, y: (x - y) % 256
add = lambda x, y: (x + y) % 256
xor = lambda x, y: (x ^ y) % 256


#1 extract the elfs.tar.xz

#2 after some basic reverse you can find 4 row of assembly that means the challenge, starting in 0x1162 offset

#3 extract them, e.g.
#   
#   echo "" > ../output_here;  ls | 
#     while read x; do 
#       echo -ne "\n\n" >> ../output_here; echo "$x" >> ../output_here ; 
#       objdump -M intel -d "$x" | grep "1162:" -A4 >> ../output_here ;
#       done

#4 clean some opcode
#   cat ../output_here | grep -e "elf" -e "mov " -e "sub" -e "add" -e "xor" -e "cmp"  > ../output_2
#
# example of a entry:
# elf_4
#    1162:	c6 45 ff 2d          	mov    BYTE PTR [rbp-0x1],0x2d
#    116a:	83 f0 2f             	xor    eax,0x2f
#    116d:	38 45 ff             	cmp    BYTE PTR [rbp-0x1],al

#5 parser
def main():
  keys = {}
  fp = open("output_2", "r")
  lol = fp.readlines()
  lol = "".join(lol).split("elf_")[1:]
  #lol[1].split("\n")[1].split("\t")[1]
  # 
  for entry in lol :
    row=entry.split("\n")
    key_now = int(row[0])
    #
    try :
      mov_byte = int((row[1].split("\t")[1]).split("c6 45 ff ")[1].rstrip(), 16)
      if (row[2].split("\t")[1]).startswith("83 ea "):  #sub
        print("sub")
        second_byte = int((row[2].split("\t")[1]).split("83 ea ")[1].rstrip(), 16)
        operation = sub 
        print("sub")
      elif (row[2].split("\t")[1]).startswith("83 f0 "):  #xor
        print("xor")
        second_byte = int((row[2].split("\t")[1]).split("83 f0 ")[1].rstrip(), 16)
        operation = xor
        print("xor")
      elif (row[2].split("\t")[1]).startswith("83 c2 "):  #add
        print("add")
        second_byte = int((row[2].split("\t")[1]).split("83 c2 ")[1].rstrip(), 16)
        operation = add
        print("add")
      # 
      for x in range(256) :
        if mov_byte == operation(x, second_byte):
          keys.update({key_now:x})
          break
    except :
      print(entry)
      return keys
  #
  return keys

output = main()
strz="".join([ chr(y) for x,y in sorted( output.items(), key=lambda x: x[0]) ])
fp = open("final", "w")
fp.write(strz)
fp.close()

