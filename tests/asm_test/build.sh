nasm -f elf64 -gdwarf main.s
ld -o asm_test main.o
