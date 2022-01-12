global _start

_start:
mov rdi, 1
mov rax, 0x000a44454b434148
push rax
mov rsi, rsp
mov rdx, 7
mov rax, 1
syscall; write(1, "HACKED\n", 7);
pop rax
mov rax, 60
mov rdi, 19
syscall; exit(19);
