#!/usr/bin/env python
from z3 import *

get_xx = lambda x, y : (x & (2**y-1))
get_32 = lambda x: get_xx(x, 32)
get_64 = lambda x: get_xx(x, 64)
get_8 = lambda x:  get_xx(x, 3)

# NOTE the imul means we ignore the upper byte, and just focus on lower byte, more here:https://stackoverflow.com/questions/42587607/why-is-imul-used-for-multiplying-unsigned-numbers
def jj_XX(next_arg, buff, s, ret):  # ( rsi:next_arg, rdx:buff, rax:return )
  s.add(Or((ret == next_arg), (ret == next_arg+buff), (ret == (next_arg-buff)), \
  (ret == get_64((next_arg * buff))), (ret ==  get_64((next_arg * next_arg))), (ret == get_64(( next_arg << get_8(buff)))), \
  (ret == ( next_arg >> get_8(buff))), (ret == ( next_arg ^ buff))))

cafe = 0xcafebabe
c1 = 0x83F66D0E3
c2 = 0x24A452F8E

s = Solver()
next_arg = BitVec('next_arg',64)
s.add( next_arg == 0xcafebabe)

next_arg1 = BitVec('next_arg1',64)
buff = BitVec('buff1',64)
buff_init = buff

jj_XX(next_arg, buff, s, next_arg1)
next_arg = next_arg1

for x in range(2, 9, 1) :
  buff_now = BitVec('buff{0}'.format(x), 64)
  s.add( buff_now == ( c1 * buff + c2 ))
  buff = buff_now
  next_arg_now = BitVec('next_arg{0}'.format(x), 64)
  jj_XX(next_arg, buff, s, next_arg_now)
  next_arg = next_arg_now

s.check()

buff_final = BitVec('buff_final',64)
s.add(buff_final == (c1 * buff + c2))
s.add(buff_final == 0x471DE8678AE30BA1)
s.add(next_arg == 0x0ACDEE2ED87A5D886)
s.check()
s.model()[buff_init] # 982730589345
# gigem{00ps_ch3ck_y0ur_7upl35}


