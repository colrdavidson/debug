[bits 64]

global _start

section .text
_start:
	mov rdi, 21
	mov rax, 60
	syscall
	nop
