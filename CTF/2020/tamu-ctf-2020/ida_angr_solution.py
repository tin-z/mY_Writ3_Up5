from pwn import *
import sys

#1 run in idapython, and search offsets starting with 'rep nop edx' instruction 
def search_pattern(pattern, counter=1):
  """
    e.g. Pattern = '55 8B EC'
  """
  addr = MinEA()
  address = []
  for x in range(0,counter):
    addr = idc.FindBinary(addr, SEARCH_DOWN|SEARCH_NEXT, pattern);
    if addr != idc.BADADDR:
      address.append(addr)
    else :
     break
  return address

#hooks_addr = search_pattern("F3 0F 1E FA", counter=1000)
hooks_addr = [ 0x1000 , 4144L, 4256L, 4272L, 4288L, 4304L, 4320L, 4336L, 4352L, 4368L, 4384L, 4544L, 4608L, 4617L, 4653L, 4690L, 4764L, 4883L, 5001L, 5071L, 5145L, 5219L, 5371L, 5492L, 5610L, 5684L, 5797L, 5962L, 6036L, 6169L, 6296L, 6370L, 6482L, 6556L, 6678L, 6854L, 7032L, 7153L, 7326L, 7440L, 7514L, 7626L, 7739L, 7813L, 7922L, 8079L, 8191L, 8303L, 9184L, 9296L, 9304L]


#2 run angr solver
def angr_solver():
  import angr
  import angr.sim_options as so
  import claripy
  global hooks_addr
  #
  def ret_nops(state):
    return
  #
  # init
  proj_name = "angrmanagement"
  proj = angr.Project(proj_name, auto_load_libs=False)
  base_address=proj.loader.main_object.min_addr
  #
  # Set hooks
  lengths = 4 # length_of_instruction
  # Extracted hooks
  hooks = [ (base_address + x, ret_nops, lengths) for x in hooks_addr ]
  for x, ff, y in hooks:
    proj.hook(x, ff, length=y)
  #
  find_addr = [ x + base_address for x in [0x2359] ]
  avoid_addr = [ x + base_address for x in [0x23B2] ]
  state = proj.factory.entry_state()
  simgr = proj.factory.simulation_manager(state)
  simgr.explore(find=find_addr, avoid=avoid_addr)
  return simgr.found[0].posix.dumps(3)

#password = list(angr_solver())
password = ['x', '#', 'P', 'i', ',', 'G', '`', 'm', 'T', '[', '$', 'D', '5', '\x06', '8', 'b', '\x10', 'h', '`', 'A', '`', '\x80', '0', '(', '`', '.', 'G', 'J', '@', 'A', '@', 'j']

#3 send password and get the flag
def solution(online):
  global password
  context.arch = 'amd64' 
  prog_name = './angrmanagement'
  context.binary = prog_name 
  ## init of python
  if( online ):
    r = remote("challenges.tamuctf.com", 4322)
  else:
    r = process(prog_name)
  #
  def halt():
    while True:
      log.info( r.recvline() )
  #
  r.recvuntil("Enter the password:")
  r.sendline("".join(password))
  r.interactive()


online = True if int(sys.argv[1])==0 else False
solution(online)

