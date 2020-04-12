import string

# the result is compared with the following string
# found in memory with gdb
strz=list("adhmp`badO|sL}JuvvFmiui{@IO}QQVRZ")

# is a stream chiper, and every char is xored with a counter starting from 7
ccounter=6
solution=[]
for index, y in enumerate(strz):
  ccounter += 1
  for x in string.printable:
    if ord(x) ^ ccounter == ord(y):
      solution.append(x)
      break

print("".join(solution))

#'flag{look_ma_i_can_write_in_rust}'

