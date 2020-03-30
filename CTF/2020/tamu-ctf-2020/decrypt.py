#!/usr/bin/env python
import string

# start revresing some, so we have strange things with rust, but we ignore all, and also focus on functions: get_flag, encrypt, decrypt
# we ignore all the lib calling, and see the simple alg used to enc
size = 28
v7 = 0xE193FE85E88DEA83L
v8 = 0xF79EC1AAD8B9CDBEL
v9 = 0xFA8FFDA2CEABCEA8L
v10 = 0xF984FD89

corrupted = ['83', 'EA', '8D', 'E8', '85', 'FE', '93', 'E1', 'BE', 'CD', 'B9', 'D8', 'AA', 'C1', '9E', 'F7', 'A8', 'CE', 'AB', 'CE', 'A2', 'FD', '8F', 'FA', \
  '89', 'FD', '84', 'F9']
corrupted = [int(x,16) for x in corrupted]
init = 0xe4
flags = [] #start_with = ord('g')

for i in range(28) :
  v8 = init
  init = corrupted[i]
  flags.append( corrupted[i] ^ v8 )

print( "".join( [chr(x) for x in flags] ) )

