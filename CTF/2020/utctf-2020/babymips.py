import string

ret = ['b', 'l', '\x7f', 'v', 'z', '{', 'f', 's', 'v', 'P', 'R', '}', '@', 'T', 'U', 'y', '@', 'I', 'G', 'M', 't', '\x19', '{', 'j', 'B', '\n', 'O', 'R', '}', 'i', 'O', 'S', '\x0c', 'd', '\x10', '\x0f', '\x1e', 'J', 'g', '\x03', '|', 'g', '\x02', 'j', '1', 'g', 'a', '7', 'z', 'b', ',', ',', '\x0f', 'n', '\x17', '\x00', '\x16', '\x0f', '\x16', '\n', 'm', 'b', 's', '%', '9', 'v', '.', '\x1c', 'c', 'x', '+', 't', '2', '\x16', ' ', '"', 'D', '\x19', '\x00', '\x00', '\x00', '\x00', '\x00', 'N'] 
ret = ret[:-6]

#varsz='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ():_{|}'
#varsz = list(string.list(string.ascii_lowercase)
varsz = string.printable[:]
solution = []#[] for _ in range(78)]
for index,elem in enumerate(ret):
  for x in varsz:
    if ord(x) ^ index + 0x17 == ord(elem):
      solution.append(x)



