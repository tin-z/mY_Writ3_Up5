
# the result is compared with the following string:"adhmp`badO|sL}JuvvFmiui{@IO}QQVRZ"
# found in memory with gdb
# is a stream chiper, and every char is xored with a counter starting from 7
print("".join([chr(ord(y) ^ (index + 7)) for index,y in enumerate(list("adhmp`badO|sL}JuvvFmiui{@IO}QQVRZ"))]))



