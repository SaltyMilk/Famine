global _start

_start:
mov ebx, 1
mov eax, 0x000a4148
push eax
mov ecx, esp
mov edx, 3
mov eax, 4
int 0x80; write(1, "HA\n", 7);
pop eax
mov eax, 1
mov ebx, 0
int 0x80; exit(19);
