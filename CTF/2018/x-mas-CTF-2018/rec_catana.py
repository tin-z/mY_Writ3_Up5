#!/usr/bin/env python
import sys

def rec_one( a1,a2,a3):
 v6 = a3
 v7 = 0;
 if( (a2 != a1) or (a3 != a1)):
  if( a2 < a1):
   v4 = rec_one(a1,a2+1, a3)
   v7 = v4
  if((v6 < a1) and (v6 < a2)):
   v5 = rec_one(a1,a2,v6+1)
   v7 += v5
  result = v7
 else :
  result = 1
 print(a1,a2,a3, "result: "+str(result))
 return result

if __name__ == "__main__":
    print( rec_one(int( sys.argv[1] ), 0, 0) )
   
