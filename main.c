#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define panic(...) do { dprintf(2, __VA_ARGS__); exit(1); } while (0)

typedef struct {
	uint8_t  e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
} Elf64_Ehdr;

static uint64_t inject_breakpoint_at_addr(int pid, uint64_t addr) {
	uint64_t orig_data = (uint64_t)ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);

	// Replace first byte of code at address with int 3
	uint64_t data_with_trap = (orig_data & 0xFFFFFFFFFFFF00) | 0xCC;
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data_with_trap);

	return orig_data;
}

static void repair_breakpoint(int pid, uint64_t addr, uint64_t orig_data) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);

	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)orig_data);
	regs.rip -= 1;
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

static int jump_to_next_breakpoint(int pid) {
	ptrace(PTRACE_CONT, pid, NULL, NULL);

	int status;
	wait(&status);
	if (!WIFSTOPPED(status)) {
		panic("Failure to break on breakpoint\n");
	}

	return 0;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		panic("Please provide the debugger a program to debug!\n");
	}

	int fd = open(argv[1], O_RDONLY);
	if (!fd) {
		panic("Failed to open %s\n", argv[1]);
	}

	off_t f_end = lseek(fd, 0, SEEK_END);
	if (f_end < 0) {
		panic("Failed to seek to end of file!\n");
	}
	lseek(fd, 0, SEEK_SET);

	uint64_t size = (uint64_t)f_end;
	uint8_t *buffer = malloc(size);
	ssize_t ret = read(fd, buffer, size);
	if (ret < 0 || (uint64_t)ret != size) {
		panic("Failed to read %s\n", argv[1]);
	}

	// Ensure that the file is an executable program
	Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *)buffer;
	if (!(elf_hdr->e_ident[0] == 0x7f &&
		  elf_hdr->e_ident[1] == 'E'  &&
		  elf_hdr->e_ident[2] == 'L'  &&
		  elf_hdr->e_ident[3] == 'F')) {
		panic("File is not a valid ELF file\n");
	}

	#define ELFCLASS64  2
	#define ELFDATA2LSB 1
	#define EM_X86_64   62
	if (elf_hdr->e_ident[4] != ELFCLASS64  ||
		elf_hdr->e_ident[5] != ELFDATA2LSB ||
		elf_hdr->e_machine  != EM_X86_64) {
		panic("This debugger only supports x86_64\n");
	}

	#define ET_EXEC     2
	if (elf_hdr->e_type != ET_EXEC) {
		panic("This debugger only supports executable files\n");
	}

	// Attempt to debug program
	int pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(argv[1], argv + 1);

		panic("Failed to run program %s\n", argv[1]);
	} else if (pid < 0) {
		panic("Failed to fork?\n");
	}

	int status;
	wait(&status);

	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	printf("RIP: %llx\n", regs.rip);
	uint64_t break_addr = regs.rip + 3;

	uint64_t orig_data = inject_breakpoint_at_addr(pid, break_addr);

	for (;;) {
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		printf("RIP: %llx\n", regs.rip);
		printf("RAX: %llx\n", regs.rax);
		printf("RBX: %llx\n", regs.rbx);
		printf("RCX: %llx\n", regs.rcx);
		printf("RDX: %llx\n", regs.rdx);
		printf("RSI: %llx\n", regs.rsi);
		printf("RDI: %llx\n", regs.rdi);
		printf("RSP: %llx\n", regs.rsp);
		printf("RBP: %llx\n", regs.rbp);
		printf("R8:  %llx\n", regs.r8);
		printf("R9:  %llx\n", regs.r9);
		printf("R10: %llx\n", regs.r10);
		printf("R11: %llx\n", regs.r11);
		printf("R12: %llx\n", regs.r12);
		printf("R13: %llx\n", regs.r13);
		printf("R14: %llx\n", regs.r14);
		printf("R15: %llx\n", regs.r15);
		printf("\n");

		if (regs.rip == break_addr) {
			printf("Hopping over breakpoint\n");
			repair_breakpoint(pid, break_addr, orig_data);
			ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
			orig_data = inject_breakpoint_at_addr(pid, break_addr);
			printf("Breakpoint restored\n");
		} else {
			ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
		}

		usleep(500000);

		wait(&status);
		if (WIFEXITED(status)) {
			return 0;
		}
	}
}
