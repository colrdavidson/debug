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

char *dwarf_tag_to_str(uint8_t id) {
	switch (id) {
		case 0:    { return "0"; } break;
		case 0x01: { return "DW_TAG_array_type"; } break;
		case 0x05: { return "DW_TAG_formal_parameter"; } break;
		case 0x0b: { return "DW_TAG_lexical_block"; } break;
		case 0x0d: { return "DW_TAG_member"; } break;
		case 0x0f: { return "DW_TAG_pointer_type"; } break;
		case 0x11: { return "DW_TAG_compile_unit"; } break;
		case 0x13: { return "DW_TAG_structure_type"; } break;
		case 0x16: { return "DW_TAG_typedef"; } break;
		case 0x1d: { return "DW_TAG_inlined_subroutine"; } break;
		case 0x21: { return "DW_TAG_subrange_type"; } break;
		case 0x2e: { return "DW_TAG_subprogram"; } break;
		case 0x24: { return "DW_TAG_base_type"; } break;
		case 0x34: { return "DW_TAG_variable"; } break;
		default:   { return "(unknown)"; }
	}
}

char *dwarf_attr_name_to_str(uint8_t attr_name) {
	switch (attr_name) {
		case 0:    { return "0"; } break;
		case 0x02: { return "DW_AT_location"; } break;
		case 0x03: { return "DW_AT_name"; } break;
		case 0x0b: { return "DW_AT_byte_size"; } break;
		case 0x10: { return "DW_AT_stmt_list"; } break;
		case 0x11: { return "DW_AT_low_pc"; } break;
		case 0x12: { return "DW_AT_high_pc"; } break;
		case 0x13: { return "DW_AT_language"; } break;
		case 0x1b: { return "DW_AT_comp_dir"; } break;
		case 0x20: { return "DW_AT_inline"; } break;
		case 0x25: { return "DW_AT_producer"; } break;
		case 0x27: { return "DW_AT_prototyped"; } break;
		case 0x31: { return "DW_AT_abstract_origin"; } break;
		case 0x37: { return "DW_AT_count"; } break;
		case 0x38: { return "DW_AT_data_member_location"; } break;
		case 0x3a: { return "DW_AT_decl_file"; } break;
		case 0x3b: { return "DW_AT_decl_line"; } break;
		case 0x3e: { return "DW_AT_encoding"; } break;
		case 0x3f: { return "DW_AT_external"; } break;
		case 0x40: { return "DW_AT_frame_base"; } break;
		case 0x49: { return "DW_AT_type"; } break;
		case 0x55: { return "DW_AT_ranges"; } break;
		case 0x57: { return "DW_AT_call_column"; } break;
		case 0x58: { return "DW_AT_call_file"; } break;
		case 0x59: { return "DW_AT_call_line"; } break;
		default:   { return "(unknown)"; }
	}
}

char *dwarf_attr_form_to_str(uint8_t attr_form) {
	switch (attr_form) {
		case 0:    { return "0"; } break;
		case 0x01: { return "DW_FORM_addr"; } break;
		case 0x05: { return "DW_FORM_data2"; } break;
		case 0x06: { return "DW_FORM_data4"; } break;
		case 0x0b: { return "DW_FORM_data1"; } break;
		case 0x0e: { return "DW_FORM_strp"; } break;
		case 0x13: { return "DW_FORM_ref4"; } break;
		case 0x17: { return "DW_FORM_sec_offset"; } break;
		case 0x18: { return "DW_FORM_exprloc"; } break;
		case 0x19: { return "DW_FORM_flag_present"; } break;
		default:   { return "(unknown)"; }
	}
}

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

	uint8_t *debug_info = NULL;
	int debug_info_size = 0;

	uint8_t *debug_abbrev = NULL;
	int debug_abbrev_size = 0;

	char *strtable = (char *)(buffer + strtable_hdr->sh_offset);
	for (int i = 0; i < elf_hdr->e_shnum; i++) {
		ELF64_Shdr *sect_hdr = (ELF64_Shdr *)(sect_hdr_buf + (i * elf_hdr->e_shentsize));

		char *section_name = strtable + sect_hdr->sh_name;

/*
		printf("- Section Name:       %s\n",  section_name);
		printf("- Section Type:       %u\n",  sect_hdr->sh_type);
		printf("- Section Size:       %lx\n", sect_hdr->sh_size);
		printf("- Section Entry Size: %lx\n", sect_hdr->sh_entsize);
		printf("- Section Offset:     %lx\n", sect_hdr->sh_offset);
*/

		char dbginfo_str[] = ".debug_info";
		char dbgabbrev_str[] = ".debug_abbrev";

		if (!(strncmp(section_name, dbginfo_str, sizeof(dbginfo_str)))) {
			debug_info = buffer + sect_hdr->sh_offset;
			debug_info_size = sect_hdr->sh_size;
		} else if (!(strncmp(section_name, dbgabbrev_str, sizeof(dbgabbrev_str)))) {
			debug_abbrev = buffer + sect_hdr->sh_offset;
			debug_abbrev_size = sect_hdr->sh_size;
		}
	}

	if (debug_info && debug_abbrev) {
		printf("Parsing .debug_info\n");
		if ((*(uint32_t *)debug_info) == 0xFFFFFFFF) {
			panic("Currently this debugger only handles 32 bit DWARF! TODO\n");
		}

		DWARF32_CUHdr *cu_hdr = (DWARF32_CUHdr *)debug_info;

		if (cu_hdr->version != 4) {
			panic("This code only supports DWARF 4, got %d!\n", cu_hdr->version);
		}

		printf("debug_info useful size: %x\n", cu_hdr->unit_length);
		printf("DWARF version: %d\n", cu_hdr->version);
		printf("debug entry abbrev offset: %x\n", cu_hdr->debug_abbrev_offset);
		printf("arch address size: %d bytes\n", cu_hdr->address_size);

		{
			uint8_t abbrev_code = *(debug_info + sizeof(DWARF32_CUHdr));
			printf("Abbreviation code: %u\n", abbrev_code);
		}

		printf("Parsing .debug_abbrev\n");
		int i = 0;
		while (i < debug_abbrev_size) {
			uint8_t abbrev_code        = debug_abbrev[i + 0];
			printf("Abbreviation code: %u\n", abbrev_code);
			if (abbrev_code == 0) {
				printf("Found the end of the abbrev table\n");
				break;
			}

			uint8_t entry_tag          = debug_abbrev[i + 1];
			uint8_t entry_has_children = debug_abbrev[i + 2];
			i += 3;

			printf("Entry Tag: %s (0x%x)\n", dwarf_tag_to_str(entry_tag), entry_tag);
			printf("Entry has children: %s\n", ((entry_has_children) ? "yes" : "no"));

			while (i < debug_abbrev_size) {
				uint8_t attr_name = debug_abbrev[i + 0];
				uint8_t attr_form = debug_abbrev[i + 1];

				printf("%s %s (0x%x, 0x%x)\n", dwarf_attr_name_to_str(attr_name), dwarf_attr_form_to_str(attr_form), attr_name, attr_form);

				i += 2;
				if (attr_name == 0 && attr_form == 0) {
					printf("Found end attribute\n");
					break;
				}
			}
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
