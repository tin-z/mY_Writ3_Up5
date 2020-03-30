from pwn import *
import string

def f0(a1, a2):
  i = 0
  output = []
  while True:
    if i >= len(a1):
      break
    for x in string.printable:
      chr_now = ord(x)
      if ( chr_now > 96 and chr_now <= 122 ):
        chr_now = (chr_now - 0x54 + a2) % 26 + 97
      if ( chr_now > 64 and chr_now <= 90 ):
        chr_now = (chr_now - 0x34 + a2) % 26 + 65
      if chr_now == a1[i] :
        output.append(ord(x))
        if i+1 < len(a1):
          output.append(a1[i+1])
        if i+2 < len(a1):
          output.append(a1[i+2])
        i += 3
        break
  return output

def f1(ptr_buff, max_val_7):
  output = [ ptr_buff[(x-max_val_7) % len(ptr_buff)] for x in range(len(ptr_buff)) ]
  return output

def f2(ptr_buff, max_val_7):
  a1 = ptr_buff
  a2 = max_val_7
  output = []
  #output.append(a1[0])
  for i in range(0,len(a1),1):  # CARE here.. start from 1 if you have problems..
    for x in string.printable:
      chr_now = ord(x)
      if ( chr_now > 47 and chr_now <= 57 ):
        chr_now += a2
      if chr_now == a1[i]:
        output.append(ord(x))
        break
  #print( "f3:", "".join( [ chr(x) for x in output]))
  return output


def test():
  rets="2020-03-23T09:13:07UTC> Encrypted password: 3geJaw7:CX4tiAbrOuj:iCet"
  rets=rets.split("> Encrypted password: ")
  minutes = int( rets[0].split(":")[-2] )
  flagz = rets[1]
  flagz = [ord(x) for x in flagz]
  f_table = [f0, f1, f2]
  val_index = (minutes % 6 ) + 2
  print(minutes, val_index)
  #print("index:{0}".format(val_index))
  for x in range(2, -1, -1):
    flagz=f_table[ (val_index + x) % 3 ](flagz, val_index) 
  print( "".join( [ chr(x) for x in flagz]))
 

r = remote("challenges.tamuctf.com", 4321)
rets=r.recvline().rstrip()
rets=rets.split("> Encrypted password: ")
minutes = int( rets[0].split(":")[-2] )
#print(minutes, rets[1])

flagz = rets[1] # e.g."sOuk;iDet4geKaw8;CY5tjA"
flagz = [ord(x) for x in flagz]
f_table = [f0, f1, f2]
val_index = (minutes % 6 ) + 2
#print("index:{0}".format(val_index))
for x in range(2, -1, -1):
  flagz=f_table[ (val_index + x) % 3 ](flagz, val_index) 

print( "".join( [ chr(x) for x in flagz]))
r.sendline( "".join( [ chr(x) for x in flagz]))
r.interactive()
# gigem{1tsAbOut7iMet0geTaw47CH}

