.global _start

.section .data
msg:    .asciz "Hello, World!\n"

.section .text
_start:
    @ syscall: write(1, msg, length)
    mov r0, #1               @ File descriptor (stdout)
    ldr r1, =msg             @ Load address of message
    mov r2, #14              @ Message length
    mov r7, #4               @ Syscall number for sys_write
    svc #0                   @ Call kernel

    @ syscall: exit(0)
    mov r0, #0               @ Exit code
    mov r7, #1               @ Syscall number for sys_exit
    svc #0                   @ Call kernel
