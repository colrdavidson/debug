#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/personality.h>

/*
 * Handy References:
 * - https://refspecs.linuxbase.org/elf/elf.pdf
 * - http://man7.org/linux/man-pages/man5/elf.5.html
 * - http://dwarfstd.org/doc/DWARF4.pdf
 * - https://wiki.osdev.org/DWARF
 */

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

typedef struct {
	uint32_t unit_length;
	uint16_t version;
	uint32_t header_length;
	uint8_t  min_inst_length;
	uint8_t  max_ops_per_inst;
	uint8_t  default_is_stmt;
	int8_t   line_base;
	int8_t   line_range;
	uint8_t  opcode_base;
} DWARF32_LineHdr;
#pragma pack()

typedef struct {
	uint8_t  id;
	uint32_t type;
	uint8_t  has_children;
	uint8_t *attr_buf;
	int      attr_count;
} AbbrevUnit;

typedef struct {
	uint64_t address;
	uint32_t op_idx;
	uint32_t file_idx;
	uint32_t line_num;
	uint32_t col_num;
	bool     is_stmt;
	bool     basic_block;
	bool     end_sequence;
	bool     prologue_end;
	bool     epilogue_begin;
	uint32_t isa;
	uint32_t discriminator;
} LineMachine;

typedef struct {
	char    *filenames[1024];
	int      file_count;
	uint64_t dir_idx[1024];
	char    *dirs[1024];
	int      dir_count;
	uint8_t *op_buf;
	uint32_t op_buf_size;
	bool     default_is_stmt;
	int8_t   line_base;
	int8_t   line_range;
	uint8_t  opcode_base;

	LineMachine *lines;
	int line_count;
	int line_max;
} CULineTable;


enum {
	SHT_NULL = 0,
	SHT_PROGBITS,
	SHT_SYMTAB,
	SHT_STRTAB,
	SHT_RELA,
	SHT_HASH,
	SHT_DYNAMIC
};

enum {
	DW_FORM_addr         = 0x01,
	DW_FORM_data2        = 0x05,
	DW_FORM_data4        = 0x06,
	DW_FORM_data1        = 0x0b,
	DW_FORM_strp         = 0x0e,
	DW_FORM_udata        = 0x0f,
	DW_FORM_ref4         = 0x13,
	DW_FORM_sec_offset   = 0x17,
	DW_FORM_exprloc      = 0x18,
	DW_FORM_flag_present = 0x19,
};

enum {
	DW_TAG_array_type         = 0x01,
	DW_TAG_formal_parameter   = 0x05,
	DW_TAG_lexical_block      = 0x0b,
	DW_TAG_member             = 0x0d,
	DW_TAG_pointer_type       = 0x0f,
	DW_TAG_compile_unit       = 0x11,
	DW_TAG_structure_type     = 0x13,
	DW_TAG_typedef            = 0x16,
	DW_TAG_inlined_subroutine = 0x1d,
	DW_TAG_subrange_type      = 0x21,
	DW_TAG_subprogram         = 0x2e,
	DW_TAG_base_type          = 0x24,
	DW_TAG_variable           = 0x34,
};

enum {
	DW_AT_location             = 0x02,
	DW_AT_name                 = 0x03,
	DW_AT_byte_size            = 0x0b,
	DW_AT_stmt_list            = 0x10,
	DW_AT_low_pc               = 0x11,
	DW_AT_high_pc              = 0x12,
	DW_AT_language             = 0x13,
	DW_AT_comp_dir             = 0x1b,
	DW_AT_const_value          = 0x1c,
	DW_AT_inline               = 0x20,
	DW_AT_producer             = 0x25,
	DW_AT_prototyped           = 0x27,
	DW_AT_abstract_origin      = 0x31,
	DW_AT_count                = 0x37,
	DW_AT_data_member_location = 0x38,
	DW_AT_decl_file            = 0x3a,
	DW_AT_decl_line            = 0x3b,
	DW_AT_encoding             = 0x3e,
	DW_AT_external             = 0x3f,
	DW_AT_frame_base           = 0x40,
	DW_AT_type                 = 0x49,
	DW_AT_ranges               = 0x55,
	DW_AT_call_column          = 0x57,
	DW_AT_call_file            = 0x58,
	DW_AT_call_line            = 0x59,
};

enum {
	DW_LNE_end_sequence = 0x01,
	DW_LNE_set_address  = 0x02
};

enum {
	DW_LNS_copy             = 0x01,
	DW_LNS_advance_pc       = 0x02,
	DW_LNS_advance_line     = 0x03,
	DW_LNS_set_file         = 0x04,
	DW_LNS_set_column       = 0x05,
	DW_LNS_negate_stmt      = 0x06,
	DW_LNS_const_add_pc     = 0x08,
	DW_LNS_set_prologue_end = 0x0a,
};


// GLOBALS

uint32_t break_line = 9;
char *break_file = "dummy.c";


int64_t get_leb128_i(uint8_t *buf, uint32_t *size) {
	uint8_t *ptr = buf;
	int64_t  result = 0;
	uint32_t shift = 0;

	uint8_t  byte;
	do {
		byte = *ptr++;
		result |= ((uint64_t)(byte & 0x7f)) << shift;
		shift += 7;
	} while (byte >= 128);

	// Fuss with negative number sign extension
	if (shift < 64 && (byte & 0x40)) {
		result |= (~0) << shift;
	}

	*size = (uint32_t)(ptr - buf);

	return result;
}

uint64_t get_leb128_u(uint8_t *buf, uint32_t *size) {
	uint8_t *ptr = buf;
	int64_t  result = 0;
	uint32_t shift = 0;

	uint8_t  byte;
	do {
		byte = *ptr++;
		result |= ((uint64_t)(byte & 0x7f)) << shift;
		shift += 7;
	} while (byte >= 128);

	*size = (uint32_t)(ptr - buf);

	return result;
}

void init_line_machine(LineMachine *lm, bool is_stmt) {
	lm->address        = 0;
	lm->op_idx         = 0;
	lm->file_idx       = 1;
	lm->line_num       = 1;
	lm->col_num        = 0;
	lm->basic_block    = false;
	lm->end_sequence   = false;
	lm->prologue_end   = false;
	lm->epilogue_begin = false;
	lm->isa            = 0;
	lm->discriminator  = 0;
	lm->is_stmt        = is_stmt;
}

char *dwarf_tag_to_str(uint8_t id) {
	switch (id) {
		case 0:    { return "0"; } break;
		case DW_TAG_array_type:         { return "DW_TAG_array_type"; } break;
		case DW_TAG_formal_parameter:   { return "DW_TAG_formal_parameter"; } break;
		case DW_TAG_lexical_block:      { return "DW_TAG_lexical_block"; } break;
		case DW_TAG_member:             { return "DW_TAG_member"; } break;
		case DW_TAG_pointer_type:       { return "DW_TAG_pointer_type"; } break;
		case DW_TAG_compile_unit:       { return "DW_TAG_compile_unit"; } break;
		case DW_TAG_structure_type:     { return "DW_TAG_structure_type"; } break;
		case DW_TAG_typedef:            { return "DW_TAG_typedef"; } break;
		case DW_TAG_inlined_subroutine: { return "DW_TAG_inlined_subroutine"; } break;
		case DW_TAG_subrange_type:      { return "DW_TAG_subrange_type"; } break;
		case DW_TAG_subprogram:         { return "DW_TAG_subprogram"; } break;
		case DW_TAG_base_type:          { return "DW_TAG_base_type"; } break;
		case DW_TAG_variable:           { return "DW_TAG_variable"; } break;
		default:   {
			if (id > 0x80) {
				panic("TODO Error on tag (0x%x) We don't actually handle LEB128\n", id);
			}
			return "(unknown)";
		}
	}
}

char *dwarf_attr_name_to_str(uint8_t attr_name) {
	switch (attr_name) {
		case 0:    { return "0"; } break;
		case DW_AT_location:             { return "DW_AT_location"; } break;
		case DW_AT_name:                 { return "DW_AT_name"; } break;
		case DW_AT_byte_size:            { return "DW_AT_byte_size"; } break;
		case DW_AT_stmt_list:            { return "DW_AT_stmt_list"; } break;
		case DW_AT_low_pc:               { return "DW_AT_low_pc"; } break;
		case DW_AT_high_pc:              { return "DW_AT_high_pc"; } break;
		case DW_AT_language:             { return "DW_AT_language"; } break;
		case DW_AT_comp_dir:             { return "DW_AT_comp_dir"; } break;
		case DW_AT_const_value:          { return "DW_AT_const_value"; } break;
		case DW_AT_inline:               { return "DW_AT_inline"; } break;
		case DW_AT_producer:             { return "DW_AT_producer"; } break;
		case DW_AT_prototyped:           { return "DW_AT_prototyped"; } break;
		case DW_AT_abstract_origin:      { return "DW_AT_abstract_origin"; } break;
		case DW_AT_count:                { return "DW_AT_count"; } break;
		case DW_AT_data_member_location: { return "DW_AT_data_member_location"; } break;
		case DW_AT_decl_file:            { return "DW_AT_decl_file"; } break;
		case DW_AT_decl_line:            { return "DW_AT_decl_line"; } break;
		case DW_AT_encoding:             { return "DW_AT_encoding"; } break;
		case DW_AT_external:             { return "DW_AT_external"; } break;
		case DW_AT_frame_base:           { return "DW_AT_frame_base"; } break;
		case DW_AT_type:                 { return "DW_AT_type"; } break;
		case DW_AT_ranges:               { return "DW_AT_ranges"; } break;
		case DW_AT_call_column:          { return "DW_AT_call_column"; } break;
		case DW_AT_call_file:            { return "DW_AT_call_file"; } break;
		case DW_AT_call_line:            { return "DW_AT_call_line"; } break;
		default:   {
			if (attr_name > 0x80) {
				panic("TODO Error on attr_name (0x%x) We don't actually handle LEB128\n", attr_name);
			}
			return "(unknown)";
		}
	}
}

char *dwarf_attr_form_to_str(uint8_t attr_form) {
	switch (attr_form) {
		case 0:                    { return "0"; } break;
		case DW_FORM_addr:         { return "DW_FORM_addr"; } break;
		case DW_FORM_data1:        { return "DW_FORM_data1"; } break;
		case DW_FORM_data2:        { return "DW_FORM_data2"; } break;
		case DW_FORM_data4:        { return "DW_FORM_data4"; } break;
		case DW_FORM_strp:         { return "DW_FORM_strp"; } break;
		case DW_FORM_udata:        { return "DW_FORM_udata"; } break;
		case DW_FORM_ref4:         { return "DW_FORM_ref4"; } break;
		case DW_FORM_sec_offset:   { return "DW_FORM_sec_offset"; } break;
		case DW_FORM_exprloc:      { return "DW_FORM_exprloc"; } break;
		case DW_FORM_flag_present: { return "DW_FORM_flag_present"; } break;
		default:   {
			if (attr_form > 0x80) {
				panic("TODO Error on attr_form (0x%x) We don't actually handle LEB128\n", attr_form);
			}
			return "(unknown)";
		}
	}
}

char *dwarf_line_ext_op_to_str(uint8_t op) {
	switch (op) {
		case DW_LNE_end_sequence:       { return "DW_LNE_end_sequence"; } break;
		case DW_LNE_set_address:        { return "DW_LNE_set_address"; } break;
		default:   {
			if (op > 0x80) {
				panic("TODO Error on line extended op (0x%x) We don't actually handle LEB128\n", op);
			}
			return "(unknown)";
		}
	}
}

char *dwarf_line_op_to_str(uint8_t op) {
	switch (op) {
		case DW_LNS_copy:             { return "DW_LNS_copy"; } break;
		case DW_LNS_advance_pc:       { return "DW_LNS_advance_pc"; } break;
		case DW_LNS_advance_line:     { return "DW_LNS_advance_line"; } break;
		case DW_LNS_set_file:         { return "DW_LNS_set_file"; } break;
		case DW_LNS_set_column:       { return "DW_LNS_set_column"; } break;
		case DW_LNS_negate_stmt:      { return "DW_LNS_negate_statment"; } break;
		case DW_LNS_set_prologue_end: { return "DW_LNS_set_prologue_end"; } break;
		case DW_LNS_const_add_pc:     { return "DW_LNS_const_add_pc"; } break;
		default:   {
			if (op > 0x80) {
				panic("TODO Error on line op (0x%x) We don't actually handle LEB128\n", op);
			}
			return "(unknown)";
		}
	}
}

void print_abbrev_table(AbbrevUnit *entries, int entry_count) {
	for (int i = 0; i < entry_count; i++) {
		AbbrevUnit *entry = &entries[i];
		printf("Entry ID: %u\n", entry->id);
		printf(" - type: %s (0x%x)\n", dwarf_tag_to_str(entry->type), entry->type);
		printf(" - children: %s\n", ((entry->has_children) ? "yes" : "no"));
		printf(" - attributes: %d\n", entry->attr_count);

		for (int j = 0; j < (entry->attr_count * 2); j += 2) {
			uint8_t attr_name = entry->attr_buf[j];
			uint8_t attr_form = entry->attr_buf[j + 1];
			printf("(0x%02x) %-18s (0x%02x) %s\n", attr_name, dwarf_attr_name_to_str(attr_name), attr_form, dwarf_attr_form_to_str(attr_form));
		}
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

	char cur_dir[PATH_MAX + 1];
	if (getcwd(cur_dir, sizeof(cur_dir)) == NULL) {
		panic("Failed to get current dir!\n");
	}

	char *bin_name = calloc(1, PATH_MAX + 1);
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
		panic("TODO This debugger requires symbols to be able to debug the file\n");
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
	uint64_t debug_info_offset = 0;
	int debug_info_size = 0;

	uint8_t *debug_abbrev = NULL;
	uint64_t debug_abbrev_offset = 0;
	int debug_abbrev_size = 0;

	uint8_t *debug_str = NULL;
	uint64_t debug_str_offset = 0;
	int debug_str_size = 0;

	uint8_t *debug_line = NULL;
	uint64_t debug_line_offset = 0;
	int debug_line_size = 0;

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
		char dbgstr_str[] = ".debug_str";
		char dbgline_str[] = ".debug_line";

		if (!(strncmp(section_name, dbginfo_str, sizeof(dbginfo_str)))) {
			debug_info_offset = sect_hdr->sh_offset;
			debug_info_size = sect_hdr->sh_size;
			debug_info = buffer + debug_info_offset;
		} else if (!(strncmp(section_name, dbgabbrev_str, sizeof(dbgabbrev_str)))) {
			debug_abbrev_offset = sect_hdr->sh_offset;
			debug_abbrev_size = sect_hdr->sh_size;
			debug_abbrev = buffer + debug_abbrev_offset;
		} else if (!(strncmp(section_name, dbgstr_str, sizeof(dbgstr_str)))) {
			debug_str_offset = sect_hdr->sh_offset;
			debug_str_size = sect_hdr->sh_size;
			debug_str = buffer + debug_str_offset;
		} else if (!(strncmp(section_name, dbgline_str, sizeof(dbgline_str)))) {
			debug_line_offset = sect_hdr->sh_offset;
			debug_line_size = sect_hdr->sh_size;
			debug_line = buffer + debug_line_offset;
		}
	}

	if (!(debug_info && debug_abbrev && debug_line)) {
		panic("TODO Currently this debugger only supports binaries with debug symbols!\n");
	}

	printf("Building the abbreviation table\n");

	#define ABBREV_MAX 1024
	int abbrev_len = 0;
	AbbrevUnit abbrev_entries[ABBREV_MAX] = {0};

	int i = 0;
	while (i < debug_abbrev_size) {
		uint8_t abbrev_code        = debug_abbrev[i + 0];
		if (abbrev_code == 0) {
			break;
		}

		if (abbrev_len + 1 > ABBREV_MAX) {
			panic("TODO This should probably be dynamic!\n");
		}

		AbbrevUnit *entry = &abbrev_entries[abbrev_len++];
		entry->id = abbrev_code;
		entry->type = debug_abbrev[i + 1];
		entry->has_children = debug_abbrev[i + 2];
		i += 3;

		entry->attr_buf = buffer + debug_abbrev_offset + i;

		int attr_count = 0;
		while (i < debug_abbrev_size) {
			uint8_t attr_name = debug_abbrev[i + 0];
			uint8_t attr_form = debug_abbrev[i + 1];

			i += 2;
			if (attr_name == 0 && attr_form == 0) {
				break;
			}

			attr_count += 1;
		}

		entry->attr_count = attr_count;
	}

	print_abbrev_table(abbrev_entries, abbrev_len);

	printf("\n");
	printf("Parsing .debug_info\n");

	i = 0;
	while (i < debug_info_size) {
		DWARF32_CUHdr *cu_hdr = (DWARF32_CUHdr *)(debug_info + i);

		if ((*(uint32_t *)debug_info) == 0xFFFFFFFF) {
			panic("TODO Currently this debugger only handles 32 bit DWARF!\n");
		}

		printf("CU size: %x\n", cu_hdr->unit_length);
		printf("DWARF version: %d\n", cu_hdr->version);
		printf("debug entry abbrev offset: %x\n", cu_hdr->debug_abbrev_offset);
		printf("arch address size: %d bytes\n", cu_hdr->address_size);

		if (cu_hdr->version != 4) {
			panic("TODO This code only supports DWARF 4, got %d!\n", cu_hdr->version);
		}
		i += sizeof(DWARF32_CUHdr);

		int child_level = 0;
		do {
			uint8_t abbrev_id = *(debug_info + i);
			i += 1;

			if (abbrev_id == 0) {
				child_level--;
				continue;
			}

			AbbrevUnit *entry = NULL;
			for (int j = 0; j < abbrev_len; j++) {
				AbbrevUnit *tmp = &abbrev_entries[j];
				if (tmp->id == abbrev_id) {
					entry = tmp;
					break;
				}
			}
			if (!entry) {
				panic("Unable to find abbrev_table entry %u\n", abbrev_id);
			}

			if (entry->has_children) {
				child_level++;
			}

			printf("Abbrev %u: (%s) [%s]\n", abbrev_id, dwarf_tag_to_str(entry->type), ((entry->has_children) ? "has children" : "no children"));
			for (int j = 0; j < (entry->attr_count * 2); j += 2) {
				uint8_t attr_name = entry->attr_buf[j];
				uint8_t attr_form = entry->attr_buf[j + 1];

				switch (attr_form) {
					case DW_FORM_strp: {
						uint32_t str_off = *((uint32_t *)(debug_info + i));
						printf("%-18s offset: (0x%x) %s\n", dwarf_attr_name_to_str(attr_name), str_off, (debug_str + str_off));

						i += sizeof(uint32_t);
					} break;
					case DW_FORM_addr: {
						uint64_t addr = *((uint64_t *)(debug_info + i));
						printf("%-18s 0x%lx\n", dwarf_attr_name_to_str(attr_name), addr);

						i += sizeof(uint64_t);
					} break;
					case DW_FORM_data1: {
						uint8_t data = *(debug_info + i);
						printf("%-18s 0x%02x\n", dwarf_attr_name_to_str(attr_name), data);

						i += sizeof(uint8_t);
					} break;
					case DW_FORM_data2: {
						uint16_t data = *((uint16_t *)(debug_info + i));
						printf("%-18s %u\n", dwarf_attr_name_to_str(attr_name), data);

						if (attr_name == DW_AT_language && data != 0x0c) {
							panic("Debugger currently only supports C99!\n");
						}

						i += sizeof(uint16_t);
					} break;
					case DW_FORM_data4: {
						uint32_t data = *((uint32_t *)(debug_info + i));
						printf("%-18s 0x%x\n", dwarf_attr_name_to_str(attr_name), data);

						i += sizeof(uint32_t);
					} break;
					case DW_FORM_udata: {
						uint32_t leb_size = 0;
						uint64_t udata = get_leb128_u(debug_info + i, &leb_size);
						printf("%-18s 0x%02lx\n", dwarf_attr_name_to_str(attr_name), udata);

						i += leb_size;
					} break;
					case DW_FORM_ref4: {
						uint32_t offset = *((uint32_t *)(debug_info + i));
						printf("%-18s 0x%x\n", dwarf_attr_name_to_str(attr_name), offset);

						i += sizeof(uint32_t);
					} break;
					case DW_FORM_sec_offset: {
						uint32_t sect_off = *((uint32_t *)(debug_info + i));

						switch (attr_name) {
							case DW_AT_stmt_list: {
								//uint8_t *line_start = debug_line + sect_off;
								printf("%-18s line offset: 0x%x\n", dwarf_attr_name_to_str(attr_name), sect_off);
							} break;
							case DW_AT_location: {
								//uint8_t *location_start = debug_line + sect_off;
								printf("%-18s location offset: 0x%x\n", dwarf_attr_name_to_str(attr_name), sect_off);
							} break;
							case DW_AT_ranges: {
								//uint8_t *ranges_start = debug_ranges + sect_off;
								printf("%-18s ranges offset: 0x%x\n", dwarf_attr_name_to_str(attr_name), sect_off);
							} break;
							default: {
								panic("DW_FORM_sec_offset: Case not handled! %u (%s)\n", attr_name, dwarf_attr_name_to_str(attr_name));
							}
						}

						i += sizeof(uint32_t);
					} break;
					case DW_FORM_exprloc: {
						uint32_t leb_size = 0;
						uint64_t length = get_leb128_u(debug_info + i, &leb_size);
						uint64_t expr_off = i + leb_size;

						printf("%-18s length: %lu, expression offset: 0x%lx\n", dwarf_attr_name_to_str(attr_name), length, (uint64_t)expr_off);
						i += leb_size + length;
					} break;
					case DW_FORM_flag_present: {
						printf("%-18s flag present\n", dwarf_attr_name_to_str(attr_name));
					} break;
					default: {
						printf("(0x%02x) %-18s (0x%02x) %s\n", attr_name, dwarf_attr_name_to_str(attr_name), attr_form, dwarf_attr_form_to_str(attr_form));
						panic("Unhandled form: (0x%02x) %s!\n", attr_form, dwarf_attr_form_to_str(attr_form));
					}
				}
			}

			printf("\n");
		} while (i < debug_info_size && child_level > 0);
	}

	#define LINE_TABLES_MAX 20
	int line_tables_len = 0;
	CULineTable *line_tables = malloc(sizeof(CULineTable) * LINE_TABLES_MAX);

	printf("Parsing .debug_line\n");
	i = 0;
	while (i < debug_line_size) {
		DWARF32_LineHdr *line_hdr = (DWARF32_LineHdr *)(debug_line + i);
		if ((*(uint32_t *)(debug_line + i)) == 0xFFFFFFFF) {
			panic("TODO Currently this debugger only handles 32 bit DWARF!\n");
		}

		CULineTable *line_table = &line_tables[line_tables_len];
		if (line_tables_len + 1 > LINE_TABLES_MAX) {
			panic("TODO make the line tables properly stretchy!\n");
		}
		line_tables_len++;

		if (line_hdr->version != 4) {
			panic("TODO This code only supports DWARF 4, got %d!\n", line_hdr->version);
		}

		if (line_hdr->opcode_base != 13) {
			panic("TODO This debugger can't handle non-standard line ops!\n");
		}
		i += sizeof(DWARF32_LineHdr);

		int op_lengths_size = line_hdr->opcode_base - 1;
		i += op_lengths_size;

		line_table->dirs[0] = cur_dir;
		int dir_count = 1;
		while (i < debug_line_size) {
			char *dirname = (char *)(debug_line + i);
			line_table->dirs[dir_count] = dirname;

			int dirname_length = strnlen(dirname, debug_line_size - i);
			i += dirname_length + 1;
			if (dirname_length == 0) {
				break;
			}

			dir_count++;
		}

		int file_count = 1;
		while (i < debug_line_size) {
			char *filename = (char *)(debug_line + i);

			int filename_length = strnlen(filename, debug_line_size - i);
			i += filename_length + 1;
			if (filename_length == 0) {
				break;
			}

			uint32_t leb_size = 0;
			uint64_t dir_idx = get_leb128_u(debug_line + i, &leb_size);
			i += leb_size;

			leb_size = 0;
			get_leb128_u(debug_line + i, &leb_size); // last modified
			i += leb_size;

			leb_size = 0;
			get_leb128_u(debug_line + i, &leb_size); // file size
			i += leb_size;

			line_table->filenames[file_count] = filename;
			line_table->dir_idx[file_count]   = dir_idx;
			file_count++;
		}

		uint32_t cu_size  = line_hdr->unit_length + sizeof(line_hdr->unit_length);
		uint32_t hdr_size = line_hdr->header_length + sizeof(line_hdr->unit_length) + sizeof(line_hdr->version) + sizeof(line_hdr->header_length);
		uint32_t rem_size = cu_size - hdr_size;

		line_table->dir_count   = dir_count;
		line_table->file_count  = file_count;
		line_table->op_buf      = debug_line + i;
		line_table->op_buf_size = rem_size;
		line_table->opcode_base = line_hdr->opcode_base;
		line_table->line_base   = line_hdr->line_base;
		line_table->line_range  = line_hdr->line_range;

		line_table->line_max    = 4096;
		line_table->lines       = calloc(sizeof(LineMachine), line_table->line_max);
		line_table->line_count  = 0;

		i += rem_size;
	}

	for (i = 0; i < line_tables_len; i++) {
		CULineTable line_table = line_tables[i];
		printf("CU Line Table %d\n", i + 1);
		printf("Files:\n");
		for (int j = 0; j < line_table.file_count; j++) {
			uint8_t dir_idx = line_table.dir_idx[j];
			char *dirname = line_table.dirs[dir_idx];

			printf("- %s/%s\n", dirname, line_table.filenames[j]);
		}
		printf("opcode base: %d\n", line_table.opcode_base);
		printf("line base: %d\n", line_table.line_base);
		printf("line range: %d\n", line_table.line_range);
		printf("default is_stmt: %d\n", line_table.default_is_stmt);
		printf("\n");
	}

	printf("Line Ops\n");
	for (i = 0; i < line_tables_len; i++) {
		CULineTable *line_table = &line_tables[i];

		LineMachine lm_state;
		init_line_machine(&lm_state, line_table->default_is_stmt);

		for (uint32_t j = 0; j < line_table->op_buf_size; j++) {
			uint8_t op_byte = *(line_table->op_buf + j);

			//printf("<xxd-check> %lx\n", ((line_table->op_buf + j) - buffer) & (~0x0F));

			if (op_byte >= line_table->opcode_base) {
				uint8_t real_op = op_byte - line_table->opcode_base;

				int line_inc = line_table->line_base + (real_op % line_table->line_range);
				int addr_inc = real_op / line_table->line_range;

				printf("Special Op: (0x%02x), Address: 0x%lx + %d, Line: %u + %d\n",
					op_byte, lm_state.address, addr_inc, lm_state.line_num, line_inc);

				lm_state.line_num += line_inc;
				lm_state.address  += addr_inc;

				memcpy(&line_table->lines[line_table->line_count++], &lm_state, sizeof(lm_state));

				lm_state.basic_block    = false;
				lm_state.prologue_end   = false;
				lm_state.epilogue_begin = false;
				lm_state.discriminator  = 0;

				continue;
			}

			switch (op_byte) {
				case 0: { // Extended Opcodes

					// uint8_t op_size = *(line_table->op_buf + j);
					j += 2;
					uint8_t real_op = *(line_table->op_buf + j);

					switch (real_op) {
						case DW_LNE_end_sequence: {
							printf("%s (0x%02x)\n", dwarf_line_ext_op_to_str(real_op), real_op);

							lm_state.end_sequence = true;

							memcpy(&line_table->lines[line_table->line_count++], &lm_state, sizeof(lm_state));
						} break;
						case DW_LNE_set_address: {
							uint64_t address = *(uint64_t *)(line_table->op_buf + j + 1);
							printf("%s (0x%02x) 0x%lx\n", dwarf_line_ext_op_to_str(real_op), real_op, address);

							lm_state.address = address;
							j += sizeof(address);

						} break;
						default: {
							panic("Unhandled extended lineVM op! %02x\n", real_op);
						}
					}
				} break;
				case DW_LNS_copy: {
					printf("%s (0x%02x)\n", dwarf_line_op_to_str(op_byte), op_byte);

					memcpy(&line_table->lines[line_table->line_count++], &lm_state, sizeof(lm_state));

					lm_state.discriminator  = 0;
					lm_state.basic_block    = false;
					lm_state.prologue_end   = false;
					lm_state.epilogue_begin = false;
				} break;
				case DW_LNS_advance_pc: {
					uint32_t leb_size = 0;
					uint64_t addr_inc = get_leb128_u(line_table->op_buf + j + 1, &leb_size);

					printf("%s (0x%02x) address: 0x%lx + %lu\n", dwarf_line_op_to_str(op_byte), op_byte, lm_state.address, addr_inc);
					lm_state.address += addr_inc;

					j += leb_size;
				} break;
				case DW_LNS_advance_line: {
					uint32_t leb_size = 0;
					int64_t line_inc = get_leb128_i(line_table->op_buf + j + 1, &leb_size);

					printf("%s (0x%02x) line: %u + %li\n", dwarf_line_op_to_str(op_byte), op_byte, lm_state.line_num, line_inc);
					lm_state.line_num += line_inc;

					j += leb_size;
				} break;
				case DW_LNS_set_file: {
					uint32_t leb_size = 0;
					uint64_t file_idx = get_leb128_u(line_table->op_buf + j + 1, &leb_size);

					printf("%s (0x%02x) file_idx: %lu\n", dwarf_line_op_to_str(op_byte), op_byte, file_idx);
					lm_state.file_idx = file_idx;

					j += leb_size;
				} break;
				case DW_LNS_set_column: {
					uint32_t leb_size = 0;
					uint64_t col_num = get_leb128_u(line_table->op_buf + j + 1, &leb_size);

					printf("%s (0x%02x) column: %lu\n", dwarf_line_op_to_str(op_byte), op_byte, col_num);
					lm_state.col_num = col_num;

					j += leb_size;
				} break;
				case DW_LNS_negate_stmt: {
					printf("%s (0x%02x) is_stmt: !%d\n", dwarf_line_op_to_str(op_byte), op_byte, lm_state.is_stmt);

					lm_state.is_stmt = !lm_state.is_stmt;
				} break;
				case DW_LNS_const_add_pc: {
					int addr_inc = (255 - line_table->opcode_base) / line_table->line_range;
					printf("%s (0x%02x) const: %d\n", dwarf_line_op_to_str(op_byte), op_byte, addr_inc);

					lm_state.address += addr_inc;
				} break;
				case DW_LNS_set_prologue_end: {
					printf("%s (0x%02x) prologue_end = true\n", dwarf_line_op_to_str(op_byte), op_byte);
					lm_state.prologue_end = true;
				} break;
				default: {
					panic("Unhandled lineVM op! %02x\n", op_byte);
				}
			}
		}
	}


	uint64_t break_addr = ~0;

	printf("\nAttempting to break in %s on line %d\n", break_file, break_line);

	for (i = 0; i < line_tables_len; i++) {
		CULineTable *line_table = &line_tables[i];
		int j;

		uint32_t break_file_idx = 0;
		for (j = 1; j < line_table->file_count; j++) {
			if (!(strcmp(line_table->filenames[j], break_file))) {
				break_file_idx = j;
				break;
			}
		}
		if (j == line_table->file_count) {
			continue;
		}

		for (int j = 0; j < line_table->line_count; j++) {
			LineMachine line = line_table->lines[j];

			if (line.line_num == break_line && break_file_idx == line.file_idx) {
				break_addr = line.address;
				break;
			}
		}
	}
	if (break_addr == (uint64_t)~0) {
		panic("Failed to find the address for line %d\n", break_line);
	}

	printf("Found a breakpoint address: 0x%lx!\n", break_addr);

	// Attempt to debug program
	int pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);

		// Turn off stack address randomization for more consistent debugging
		personality(ADDR_NO_RANDOMIZE);

		execvp(bin_name, argv + 1);

		panic("Failed to run program %s\n", bin_name);
	} else if (pid < 0) {
		panic("Failed to fork?\n");
	}

	int status;
	wait(&status);

	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	uint64_t orig_data = inject_breakpoint_at_addr(pid, break_addr);
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait(&status);
	if (WIFEXITED(status)) {
		panic("Bailed before reaching main?\n");
	}

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
		printf("EFLAGS: %llx\n", regs.eflags);
		printf("cs: %llx\n", regs.cs);
		printf("ss: %llx\n", regs.ss);
		printf("ds: %llx\n", regs.ds);
		printf("es: %llx\n", regs.es);
		printf("fs: %llx\n", regs.fs);
		printf("gs: %llx\n", regs.gs);
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
