#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#define panic(...) do { dprintf(2, __VA_ARGS__); exit(1); } while (0)

#pragma pack(1)
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

typedef struct {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	uint64_t sh_entsize;
} ELF64_Shdr;

typedef struct {
	uint32_t unit_length;
	uint16_t version;
	uint32_t debug_abbrev_offset;
	uint8_t  address_size;
} DWARF32_CUHdr;
#pragma pack()

enum {
	SHT_NULL = 0,
	SHT_PROGBITS,
	SHT_SYMTAB,
	SHT_STRTAB,
	SHT_RELA,
	SHT_HASH,
	SHT_DYNAMIC
};

static uint64_t inject_breakpoint_at_addr(int pid, uint64_t addr) {
	uint64_t orig_data = (uint64_t)ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);

	// Replace first byte of code at address with int 3
	uint64_t data_with_trap = (orig_data & (~0xFF)) | 0xCC;
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data_with_trap);

	return orig_data;
}

static void repair_breakpoint(int pid, uint64_t addr, uint64_t orig_data) {
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)orig_data);
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

int open_binary(char *name, char **prog_path) {
	int fd;

	fd = open(name, O_RDONLY);
	if (fd >= 0) {
		*prog_path = name;
		return fd;

	}
	close(fd);

	char *path = getenv("PATH");
	char *tmp = NULL;
	do {
		tmp = strchr(path, ':');
		if (tmp != NULL) {
			tmp[0] = 0;
		}

		uint64_t path_len = snprintf(*prog_path, PATH_MAX, "%s/%s", path, name);
		fd = open(*prog_path, O_RDONLY);
		if (fd >= 0) {
			return fd;
		}

		close(fd);

		memset(*prog_path, 0, path_len);
		path = tmp + 1;
	} while (tmp != NULL);

	return -1;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		panic("Please provide the debugger a program to debug!\n");
	}

	char *bin_name = calloc(1, PATH_MAX);
	int fd = open_binary(argv[1], &bin_name);
	if (fd < 0) {
		panic("Failed to open program %s\n", argv[1]);
	}

	printf("Debugging %s\n", bin_name);

	off_t f_end = lseek(fd, 0, SEEK_END);
	if (f_end < 0) {
		panic("Failed to seek to end of file!\n");
	}
	lseek(fd, 0, SEEK_SET);

	uint64_t size = (uint64_t)f_end;
	uint8_t *buffer = malloc(size);
	ssize_t ret = read(fd, buffer, size);
	if (ret < 0 || (uint64_t)ret != size) {
		panic("Failed to read %s\n", bin_name);
	}
	close(fd);

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

	#define ET_EXEC  2
	#define ET_DYN   3
	if (!(elf_hdr->e_type == ET_EXEC || elf_hdr->e_type == ET_DYN)) {
		panic("This debugger only supports executable files\n");
	}

	if (!elf_hdr->e_shstrndx) {
		panic("I'd like a string table please! TODO\n");
	}

	printf("ELF entry location:            %lu\n", elf_hdr->e_entry);
	printf("ELF header size:               %d\n",  elf_hdr->e_ehsize);
	printf("ELF program header entry size: %d\n",  elf_hdr->e_phentsize);
	printf("ELF program header offset:     %lu\n", elf_hdr->e_phoff);
	printf("ELF program header entries:    %d\n",  elf_hdr->e_phnum);
	printf("ELF program header size:       %d\n",  elf_hdr->e_phentsize * elf_hdr->e_phnum);
	printf("ELF section header entry size: %d\n",  elf_hdr->e_shentsize);
	printf("ELF section header offset:     %lu\n", elf_hdr->e_shoff);
	printf("ELF section header entries:    %d\n",  elf_hdr->e_shnum);
	printf("ELF section header size:       %d\n",  elf_hdr->e_shentsize * elf_hdr->e_shnum);

	uint8_t *sect_hdr_buf = buffer + elf_hdr->e_shoff;
	ELF64_Shdr *strtable_hdr = (ELF64_Shdr *)(sect_hdr_buf + (elf_hdr->e_shstrndx * elf_hdr->e_shentsize));
	if (strtable_hdr->sh_type != SHT_STRTAB) {
		panic("Executable string table appears invalid!\n");
	}

	char *strtable = (char *)(buffer + strtable_hdr->sh_offset);
	for (int i = 0; i < elf_hdr->e_shnum; i++) {
		ELF64_Shdr *sect_hdr = (ELF64_Shdr *)(sect_hdr_buf + (i * elf_hdr->e_shentsize));

		char *section_name = strtable + sect_hdr->sh_name;

		char dbginfo_str[] = ".debug_info";
		if (!(strncmp(section_name, dbginfo_str, sizeof(dbginfo_str)))) {
			printf("- Section Name:       %s\n",  strtable + sect_hdr->sh_name);
			printf("- Section Type:       %u\n",  sect_hdr->sh_type);
			printf("- Section Size:       %lx\n", sect_hdr->sh_size);
			printf("- Section Entry Size: %lx\n", sect_hdr->sh_entsize);
			printf("- Section Offset:     %lx\n", sect_hdr->sh_offset);

			uint8_t *dbg_info = buffer + sect_hdr->sh_offset;
			if ((*(uint32_t *)dbg_info) == 0xFFFFFFFF) {
				panic("Currently this debugger only handles a 32 bit DWARF .debug_info! TODO\n");
			}

			DWARF32_CUHdr *cu_hdr = (DWARF32_CUHdr *)(buffer + sect_hdr->sh_offset);

			if (cu_hdr->version != 4) {
				panic("This code only supports DWARF 4, got %d!\n", cu_hdr->version);
			}

			printf("debug_info useful size: %x\n", cu_hdr->unit_length);
			printf("DWARF version: %d\n", cu_hdr->version);
			printf("debug entry abbrev offset: %x\n", cu_hdr->debug_abbrev_offset);
			printf("arch address size: %d bytes\n", cu_hdr->address_size);

			break;
		}
	}

	// Attempt to debug program
	int pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(bin_name, argv + 1);

		panic("Failed to run program %s\n", bin_name);
	} else if (pid < 0) {
		panic("Failed to fork?\n");
	}

	int status;
	wait(&status);

	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	uint64_t break_addr = regs.rip + 3;

	uint64_t orig_data = inject_breakpoint_at_addr(pid, break_addr);

	for (;;) {
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		uint64_t cur_inst = ptrace(PTRACE_PEEKTEXT, pid, (void *)regs.rip, NULL);

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
		printf("Current Inst: 0x%lx\n", cur_inst);

		if (regs.rip == break_addr) {
			printf("Hopping over breakpoint\n");

			repair_breakpoint(pid, break_addr, orig_data);

			ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

			wait(&status);
			if (WIFEXITED(status)) {
				return 0;
			}

			orig_data = inject_breakpoint_at_addr(pid, break_addr);
			printf("Breakpoint restored\n");
		} else {
			ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

			wait(&status);
			if (WIFEXITED(status)) {
				return 0;
			}
		}

		printf("\n");
		usleep(500000);
	}
}
