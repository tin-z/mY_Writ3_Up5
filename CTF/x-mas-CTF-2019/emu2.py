#!/usr/bin/env python3
import sys

class emu2():
  def __init__(self, emuInput):
    self.reg_a = 0
    self.reg_pc = 0x100
    self.fp = emuInput
    self.debugging = False
    self.strace = []
    self.stdout = []
    self.init_memory()
    self.init_loader()

  def init_memory(self):
    self.mems = [ 0 for _ in range(2**16)]
    self.perms = [ 7 for _ in range(2**16)]
    self.symtable =  \
      ["Add", "Set", "Xor", "Or", "And", "Set8", "Xor8", "Set8F", "Out", "Jmp", "Jmp0", "Jmp1", "Jmp2", "Cmp", "Cmp8", "Beef", "Lock", "Unlock", "Frob", "Nop"]
    self.break_sym = {x:0 for x  in self.symtable}
    self.breaks = [ 0 for _ in range(2**16)]

  def init_loader(self):
    try:
      tmpz = open(self.fp, "rb")
      for idx, elem in enumerate( [int(x) for x in tmpz.read()] ):
        if elem > 255:
          print("some invalid elem..?")
        self.mems[0x100 + idx] = elem
      tmpz.close()
    except:
      self.PANIC = True
  
  # Global var decode
  is_Some  = lambda x, y: x == y
  is_Some8 = lambda x, y: (x >> 4) == y
  is_Add  = lambda x : emu2.is_Some(x,0)
  is_Set  = lambda x : emu2.is_Some(x,1)
  is_Xor  = lambda x : emu2.is_Some(x,2)
  is_Or   = lambda x : emu2.is_Some(x,3)
  is_And  = lambda x : emu2.is_Some(x,4)
  is_Set8F = lambda x: emu2.is_Some8(x,0xf)
  is_Nop  = lambda x : emu2.is_Some(x, 0xee)
  is_Xor8 = lambda x : emu2.is_Some8(x, 0xd)
  is_Frob = lambda x : emu2.is_Some8(x, 0xc)
  is_Beef = lambda x : emu2.is_Some(x, 0xBE)
  is_Unlock=lambda x : emu2.is_Some8(x, 0xa)
  is_Lock = lambda x : emu2.is_Some8(x, 0x9)
  is_Set8 = lambda x : emu2.is_Some8(x, 0x8)
  is_Cmp8 = lambda x : emu2.is_Some8(x, 0x7)
  is_Cmp  = lambda x : emu2.is_Some8(x, 0x6)
  is_Jmp2 = lambda x : emu2.is_Some8(x, 0x5)
  is_Jmp1 = lambda x : emu2.is_Some8(x, 0x4)
  is_Jmp0 = lambda x : emu2.is_Some8(x, 0x3)
  is_Jmp  = lambda x : emu2.is_Some8(x, 0x2)
  is_Out  = lambda x : emu2.is_Some(x, 0x13)

  def execute(self, runs):
    runs()
    #if self.debugging:
    #  self.strace.append("Opcode:{0}\t".format(hex( self.mems[self.reg_pc] + (self.mems[self.reg_pc-1] << 8))[2:].rjust(4, "0")))
    #  self.strace[len(self.strace) -1] = self.strace[len(self.strace) - 1] + ("PC:{0}, A:{1},\t {2}".format( hex( self.reg_pc - 1)[2:].rjust(4, "0"), hex( self.reg_a)[2:].rjust(4, "0"), runs.__name__))
    #  if runs.__name__ == "Out":
    #    self.strace[len(self.strace) -1] = self.strace[len(self.strace) - 1] + "\t\"" + "".join(self.stdout)
    #  print(self.strace[len(self.strace)-1])

  def decode(self, opcode):
    if emu2.is_Add(opcode):
      return self.Add
    elif emu2.is_Set(opcode):
      return self.Set
    elif emu2.is_Xor(opcode):
      return self.Xor
    elif emu2.is_Or(opcode):
      return self.Or
    elif emu2.is_And(opcode):
      return self.And
    elif emu2.is_Set8F(opcode):
      return self.Set8F
    elif emu2.is_Nop(opcode):
      return self.Nop
    elif emu2.is_Xor8(opcode):
      return self.Xor8
    elif emu2.is_Frob(opcode):
      return self.Frob
    elif emu2.is_Beef(opcode):
      if  self.mems[self.reg_pc] == 0xef:
        return self.Beef
      else :
        pass
    elif emu2.is_Unlock(opcode):
      return self.Unlock
    elif emu2.is_Lock(opcode):
      return self.Lock
    elif emu2.is_Set8(opcode):
      return self.Set8
    elif emu2.is_Cmp8(opcode):
      return self.Cmp8
    elif emu2.is_Cmp(opcode):
      return self.Cmp
    elif emu2.is_Jmp2(opcode):
      return self.Jmp2
    elif emu2.is_Jmp1(opcode):
      return self.Jmp1
    elif emu2.is_Jmp0(opcode):
      return self.Jmp0
    elif emu2.is_Jmp(opcode):
      return self.Jmp
    elif emu2.is_Out(opcode):
      if  self.mems[self.reg_pc] == 0x37:
        return self.Out
      else :
        pass
    elif emu2.is_Nop(opcode):
      return self.Nop
    self.reg_a = (self.reg_a - 1) % (2**8)
    return self.Nop

  # Mems op
  def get(self):
    return self.mems[self.reg_pc]
  def get8(self):
    return self.mems[self.reg_pc] + ((self.mems[self.reg_pc-1] & 0xf) << 8)
  # Arithmetic Op
  def Add(self):
    self.reg_a = (self.reg_a + self.get()) % (2**8)
  def Set(self):
    self.reg_a = self.get()
  def Xor(self):
    self.reg_a = self.reg_a ^ self.get()
  def Or(self):
    self.reg_a = self.reg_a | self.get()
  def And(self):
    self.reg_a = self.reg_a & self.get()
  def Set8(self):
    self.reg_a = self.mems[self.get8()] % (2**8)
  def Xor8(self):
    tmps_8 = self.get8()
    if (self.perms[tmps_8] & 0x2):
      self.mems[tmps_8] = (self.mems[tmps_8] ^ self.reg_a) % (2**8)
  def Set8F(self):
    tmps_8 = self.get8()
    if (self.perms[tmps_8] & 0x2):
      self.mems[tmps_8] = self.reg_a
  # I/O op
  def Out(self):
    self.stdout.append(chr(self.reg_a))
    print("{0}".format(chr(self.reg_a)))
  # Control Flow op
  def Jmp(self):
    self.reg_pc = self.get8() - 1
  def Jmp0(self):
    if self.reg_a == 0:
      self.Jmp()
  def Jmp1(self):
    if self.reg_a == 1:
      self.Jmp()
  def Jmp2(self):
    if self.reg_a == 255:
      self.Jmp()
  def Cmp(self, is_8=False):
    tmpz = self.reg_a - ( self.mems[self.get8()] if( is_8 ) else self.get() )
    rets = 0
    if (tmpz > 0):
      rets = 255
    elif (tmpz < 0):
      rets = 1
    self.reg_a = rets
  def Cmp8(self):
    self.Cmp(is_8=True)
  def Beef(self):
    if( self.mems[self.reg_pc] == 0xef ):
      self.reg_pc = 0x100 - 1
      self.reg_a = 0x42
  def Lock(self):
    tmps_8 = self.get8()
    self.perms[tmps_8] = self.perms[tmps_8] & 5
  def Unlock(self):
    tmps_8 = self.get8()
    self.perms[tmps_8] = self.perms[tmps_8] | 2
  def Frob(self):
    tmps_8 = self.get8()
    if (self.perms[tmps_8] & 0x2):
      self.mems[tmps_8] = self.mems[tmps_8] ^ 0x42
  def Nop(self):
    pass
 
  def step(self):
    self.reg_a = self.reg_a % (2**8)
    opcode = self.mems[self.reg_pc]
    self.reg_pc += 1
    self.execute( self.decode(opcode) )
    self.reg_pc += 1
  
  def run(self, limit=-1, strace=False):
    ccounter = 0
    if strace:
      self.debugging = True
    try:
      while ccounter != limit:
        self.step()
        ccounter += 1
    except Exception as ex:
      return self.quit_emu2(ex)
    return self.quit_emu2(Exception("This isn't an exception.. all went good"))

  def quit_emu2(self, ex):
    print(ex.args[0])
    print("Exectuion ended.. or something bad happened..")
    print("PC:{0}".format(hex( self.reg_pc)[2:].rjust(4, "0")))
    print("STDOUT:{0}".format("".join(self.stdout)))
    print("[+] Done")
    return self.strace

  def rundbg(self):
    try:
      print("[+] Debugger ready")
      cmds = "context"
      prec = cmds
      cont = False
      while True:
        if cont:
          opcode = self.mems[self.reg_pc]
          self.reg_pc += 1
          opcode = (self.decode(opcode)).__name__
          self.reg_pc -= 1
          try:
            if self.break_sym[opcode]:
              cont = False
              cmds = "context"
              pass
          except:
            print("Warning cotinue cannot find sym:{0} ..this is strange".format(opcode_f))

          try:
            if self.breaks[self.reg_pc]:
              cont = False
              cmds = "context"
              pass
          except:
            print("Warning cotinue cannot find sym:{0} ..this is strange".format(opcode_f))

          self.step()
        else:
          prec = cmds
          opcode_tmps = self.mems[self.reg_pc]
          self.reg_pc += 1
          opcode_tmps = (self.decode(opcode_tmps)).__name__
          self.reg_pc -= 1
          print("{0}:{1} {2}".format( self.print_4k(self.reg_pc), self.print_4k( self.mems[self.reg_pc+1] + (self.mems[self.reg_pc ] << 8)), opcode_tmps))
          cmds = input("> ").rstrip()
          if cmds == "":
            cmds = prec

          if cmds == "context":
            self.print_state()
          elif cmds == "si" or cmds == "step-in":
            self.step()
          elif cmds == "h" or cmds == "help":
            self.print_help()
          elif cmds.startswith("memory"):
            tmps_1 = cmds.split(" ")
            try :
              tmps_2 = int(tmps_1[1],16)
              print("{0}: {1}".format(self.print_4k(tmps_2), self.print_4k(self.mems[tmps_2])))
            except :
              print("Warning: Invalid input{0}".format(cmds))

          elif cmds.startswith("sym-break"):
            tmps_1 = cmds.split(" ")
            self.break_sym[tmps_1[1].rstrip()]=1
          elif cmds.startswith("break"):
            tmps_1 = cmds.split(" ")
            self.breaks[int(tmps_1[1].rstrip(),16)]=1
          elif cmds == "continue" or cmds == "c":
            cont = True
            pass
          elif cmds == "quit" or cmds == "q":
            print("[+] Debugging terminated.. exit")
            break
    except Exception as ex:
      return self.quit_emu2(ex)
    return self.quit_emu2(Exception("This isn't an exception.. all went good"))

  def print_state(self):
    print("OK")
    print("\n\n| Register |\nPC:{0}\tA:{1}\n\n| Instruction |\n\tPC-2\t{2}\n\tPC -->\t{3}\n\tPC+2\t{4}\n\n".format(
      hex( self.reg_pc)[2:].rjust(4, "0"), 
      hex( self.reg_a)[2:].rjust(4, "0"), 
      self.print_4k( self.mems[self.reg_pc-1] + (self.mems[self.reg_pc - 2] << 8)),
      self.print_4k( self.mems[self.reg_pc+1] + (self.mems[self.reg_pc ] << 8)),
      self.print_4k( self.mems[self.reg_pc+3] + (self.mems[self.reg_pc + 2] << 8))))

  def print_4k(self,args):
    return hex(args)[2:].rjust(4,"0")

  def print_help(self):
    print("\n\n\thelp, h\t to show this message\n\tstep-in, si\t to one step forward the instruction\n\tcontext\t to see the status register and instruction\n\tquit, q\t to quit the gdb session.\n\n")


