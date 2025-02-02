.global _start

.data
h: .asciz "hello fucking world\n"

.section .text
_start:
    ldr r1, =h
    mov r2, #21
    mov r7, #4
    swi 0

    mov r7, #1
    mov r0, #0
    swi 0

