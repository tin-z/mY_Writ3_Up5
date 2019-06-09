#!/usr/bin/env python
import sys, struct

######### Here iter
archive = [[1],[1],[1,1],[1,2,2],[1,3,5,5]]
prec_1 = 14

def iter_one(n):
 global archive
 global prec_1
 ret = 0
 try:
     for x in archive[n]:
         ret += x
 except IndexError:
     for x in range( len(archive) , n+1):
         danza(x)
     ret = prec_1
 return ret

def danza(intero):
    x=intero
    y=x
    som = 0
    new_arch = []
    global archive
    global prec_1
    
    while(y > 0):
        ccount=0
        if(x == y):
            ccount = 1
        elif(x == (y+1)):
            ccount = y
        elif((y == 2) or (y == 1)):
            ccount = prec_1
        else:
            i = 0
            while( i < (y)):
                tail = archive.pop()
                ccount += tail[i]
                archive += [ tail ]
                i += 1
                #print("   >",y, tail[i])
        new_arch += [ccount]
        som+= ccount
        #print(x,y,som)
        y -= 1
    new_arch.sort()
    archive +=[new_arch]
    prec_1 = som



def main():
  filez = open("catana", "r+b")
  size_array = 252
  values_array = []
  offset_start = 0x1060
  offset_end = 0x1840
  #read old values 
  filez.seek(offset_start)
  for j in range(size_array):
     v3,=struct.unpack("Q", filez.read(8))
     values_array.append(v3)
     #print(j,v3)
  #now update the elf
  filez.seek(offset_start)
  #print(len(values_array))
  #print(values_array)
  for j in range(size_array):
      v3 = values_array[j] * iter_one( j % 36 ) 
      print("int: ",v3)
      v3 = struct.pack("Q", v3)
      print("byte: ",v3)
      filez.write(v3)
  filez.close()
  print("## Done!")


if __name__ == "__main__":
    main()
    #print( iter_one(int( sys.argv[1] )) )
    #print("prec:",prec_1)
    #print("archive:", archive)
    
