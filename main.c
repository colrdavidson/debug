#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
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
	uint64_t id;
	uint64_t cu_idx;

	uint32_t type;
	uint8_t  has_children;

	uint8_t *attr_buf;
	int      attr_count;
} AbbrevUnit;

typedef struct {
	uint8_t  has_children;

	uint64_t idx;
	uint64_t parent_idx;
	uint64_t cu_idx;
	uint64_t au_idx;

	uint8_t *attr_buf;
	int      attr_count;

	uint32_t type;
	uint64_t au_offset;
	uint64_t type_offset;

	char *name;

	uint8_t *loc_expr;
	int loc_expr_len;

	uint8_t *frame_base_expr;
	int frame_base_expr_len;

	uint64_t low_pc;
	uint64_t high_pc;
} Block;

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

#define DWARF_FORM \
	X(DW_FORM_addr, 0x01) \
	X(DW_FORM_data2, 0x05) \
	X(DW_FORM_data4, 0x06) \
	X(DW_FORM_data1, 0x0b) \
	X(DW_FORM_strp, 0x0e) \
	X(DW_FORM_udata, 0x0f) \
	X(DW_FORM_ref4, 0x13) \
	X(DW_FORM_sec_offset, 0x17) \
	X(DW_FORM_exprloc, 0x18) \
	X(DW_FORM_flag_present, 0x19)

#define DWARF_TAG \
	X(DW_TAG_array_type, 0x01) \
	X(DW_TAG_formal_parameter, 0x05) \
	X(DW_TAG_lexical_block, 0x0b) \
	X(DW_TAG_member, 0x0d) \
	X(DW_TAG_pointer_type, 0x0f) \
	X(DW_TAG_compile_unit, 0x11) \
	X(DW_TAG_structure_type, 0x13) \
	X(DW_TAG_typedef, 0x16) \
	X(DW_TAG_inlined_subroutine, 0x1d) \
	X(DW_TAG_subrange_type, 0x21) \
	X(DW_TAG_subprogram, 0x2e) \
	X(DW_TAG_base_type, 0x24) \
	X(DW_TAG_variable, 0x34) \

#define DWARF_AT \
	X(DW_AT_location, 0x02) \
	X(DW_AT_name, 0x03) \
	X(DW_AT_byte_size, 0x0b) \
	X(DW_AT_stmt_list, 0x10) \
	X(DW_AT_low_pc, 0x11) \
	X(DW_AT_high_pc, 0x12) \
	X(DW_AT_language, 0x13) \
	X(DW_AT_comp_dir, 0x1b) \
	X(DW_AT_const_value, 0x1c) \
	X(DW_AT_inline, 0x20) \
	X(DW_AT_producer, 0x25) \
	X(DW_AT_prototyped, 0x27) \
	X(DW_AT_abstract_origin, 0x31) \
	X(DW_AT_count, 0x37) \
	X(DW_AT_data_member_location, 0x38) \
	X(DW_AT_decl_file, 0x3a) \
	X(DW_AT_decl_line, 0x3b) \
	X(DW_AT_encoding, 0x3e) \
	X(DW_AT_external, 0x3f) \
	X(DW_AT_frame_base, 0x40) \
	X(DW_AT_type, 0x49) \
	X(DW_AT_ranges, 0x55) \
	X(DW_AT_call_column, 0x57) \
	X(DW_AT_call_file, 0x58) \
	X(DW_AT_call_line, 0x59)

#define DWARF_LINE \
	X(DW_LNE_end_sequence, 0x01) \
	X(DW_LNE_set_address, 0x02)

#define DWARF_LNS \
	X(DW_LNS_copy, 0x01) \
	X(DW_LNS_advance_pc, 0x02) \
	X(DW_LNS_advance_line, 0x03) \
	X(DW_LNS_set_file, 0x04) \
	X(DW_LNS_set_column, 0x05) \
	X(DW_LNS_negate_stmt, 0x06) \
	X(DW_LNS_const_add_pc, 0x08) \
	X(DW_LNS_set_prologue_end, 0x0a)

#define DWARF_OP \
	X(DW_OP_addr, 0x03) \
	X(DW_OP_deref, 0x06) \
	X(DW_OP_const1u, 0x08) \
	X(DW_OP_const1s, 0x09) \
	X(DW_OP_const2u, 0x0a) \
	X(DW_OP_const2s, 0x0b) \
	X(DW_OP_const4u, 0x0c) \
	X(DW_OP_const4s, 0x0d) \
	X(DW_OP_const8u, 0x0e) \
	X(DW_OP_const8s, 0x0f) \
	X(DW_OP_constu, 0x10) \
	X(DW_OP_consts, 0x11) \
	X(DW_OP_dup, 0x12) \
	X(DW_OP_drop, 0x13) \
	X(DW_OP_over, 0x14) \
	X(DW_OP_pick, 0x15) \
	X(DW_OP_swap, 0x16) \
	X(DW_OP_rot, 0x17) \
	X(DW_OP_xderef, 0x18) \
	X(DW_OP_abs, 0x19) \
	X(DW_OP_and, 0x1a) \
	X(DW_OP_div, 0x1b) \
	X(DW_OP_minus, 0x1c) \
	X(DW_OP_mod, 0x1d) \
	X(DW_OP_mul, 0x1e) \
	X(DW_OP_neg, 0x1f) \
	X(DW_OP_not, 0x20) \
	X(DW_OP_or, 0x21) \
	X(DW_OP_plus, 0x22) \
	X(DW_OP_plus_uconst, 0x23) \
	X(DW_OP_shl, 0x24) \
	X(DW_OP_shr, 0x25) \
	X(DW_OP_shra, 0x26) \
	X(DW_OP_xor, 0x27) \
	X(DW_OP_bra, 0x28) \
	X(DW_OP_eq, 0x29) \
	X(DW_OP_ge, 0x2a) \
	X(DW_OP_gt, 0x2b) \
	X(DW_OP_le, 0x2c) \
	X(DW_OP_lt, 0x2d) \
	X(DW_OP_ne, 0x2e) \
	X(DW_OP_skip, 0x2f) \
	X(DW_OP_regx, 0x90) \
	X(DW_OP_fbreg, 0x91) \

#define X(name, value) name = value,
enum { DWARF_FORM };
enum { DWARF_TAG };
enum { DWARF_AT };
enum { DWARF_LINE };
enum { DWARF_LNS };
enum { DWARF_OP };
#undef X


// GLOBALS

uint32_t break_line = 5;
char *break_file = "dummy.c";

uint64_t get_regval_for_dwarf_reg(struct user_regs_struct *regs, uint8_t idx) {
	switch (idx) {
		case 0: { return regs->rax; } break;
		case 1: { return regs->rdx; } break;
		case 2: { return regs->rcx; } break;
		case 3: { return regs->rbx; } break;
		case 4: { return regs->rsi; } break;
		case 5: { return regs->rdi; } break;
		case 6: { return regs->rbp; } break;
		case 7: { return regs->rsp; } break;
		case 8: { return regs->r8; } break;
		case 9: { return regs->r9; } break;
		case 10: { return regs->r10; } break;
		case 11: { return regs->r11; } break;
		case 12: { return regs->r12; } break;
		case 13: { return regs->r13; } break;
		case 14: { return regs->r14; } break;
		case 15: { return regs->r15; } break;
//		case 16: { return regs->ra; } break;
/*
		case 17: { return regs->xmm0; } break;
		case 18: { return regs->xmm1; } break;
		case 19: { return regs->xmm2; } break;
		case 20: { return regs->xmm3; } break;
		case 21: { return regs->xmm4; } break;
		case 22: { return regs->xmm5; } break;
		case 23: { return regs->xmm6; } break;
		case 24: { return regs->xmm7; } break;
		case 25: { return regs->xmm8; } break;
		case 26: { return regs->xmm9; } break;
		case 27: { return regs->xmm10; } break;
		case 28: { return regs->xmm11; } break;
		case 29: { return regs->xmm12; } break;
		case 30: { return regs->xmm13; } break;
		case 31: { return regs->xmm14; } break;
		case 32: { return regs->xmm15; } break;
*/
	}	
	return 0;
}


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
		#define X(name, value) case name: { return #name; } break;
			DWARF_TAG
		#undef X
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
		#define X(name, value) case name: { return #name; } break;
			DWARF_AT
		#undef X
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
		#define X(name, value) case name: { return #name; } break;
			DWARF_FORM
		#undef X
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
		#define X(name, value) case name: { return #name; } break;
			DWARF_LINE
		#undef X
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
		#define X(name, value) case name: { return #name; } break;
			DWARF_LNS
		#undef X
		default:   {
			if (op > 0x80) {
				panic("TODO Error on line op (0x%x) We don't actually handle LEB128\n", op);
			}
			return "(unknown)";
		}
	}
}

char *dwarf_expr_op_to_str(uint8_t expr_op) {
	static char op_str_cache[16];

	if (expr_op >= 0x30 && expr_op <= 0x4f) {
		sprintf(op_str_cache, "DW_OP_lit%d", expr_op - 0x30);
		return op_str_cache;
	}

	if (expr_op >= 0x50 && expr_op <= 0x6f) {
		sprintf(op_str_cache, "DW_OP_reg%d", expr_op - 0x50);
		return op_str_cache;
	}

	if (expr_op >= 0x71 && expr_op <= 0x8f) {
		sprintf(op_str_cache, "DW_OP_breg%d", expr_op - 0x71);
		return op_str_cache;
	}

	switch (expr_op) {
		#define X(name, value) case name: { return #name; } break;
			DWARF_OP
		#undef X
		default:   {
			return "(unknown)";
		}
	}
}

void print_abbrev_table(AbbrevUnit *entries, int entry_count) {
	for (int i = 0; i < entry_count; i++) {
		AbbrevUnit *entry = &entries[i];
		printf("Entry ID: %lu || CU: %lu\n", entry->id, entry->cu_idx);
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
	uint64_t orig_data = (uint64_t)ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);

	// Replace first byte of code at address with int 3
	printf("data: %lx\n", orig_data);
	uint64_t data_with_trap = (orig_data & (~0xFF)) | 0xCC;
	printf("trap data: %lx\n", data_with_trap);
	ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)data_with_trap);

	return orig_data;
}

static void repair_breakpoint(int pid, uint64_t addr, uint64_t orig_data) {
	ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)orig_data);
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

typedef enum {
	DWString,
	DWIVal,
	DWUVal,
	DWOffset,
	DWAddr,
	DWExpr
} DWType;

typedef struct {
	DWType type;
	union {
		uint64_t val;
		uint8_t *expr;
		char *str;
	} data;
	int size;
	int skip;
} DWResult;

typedef struct {
	uint8_t *debug_info;
	int debug_info_size;
	uint8_t *debug_line;
	int debug_line_size;
	uint8_t *debug_str;
	int debug_str_size;
	uint8_t *debug_abbrev;
	int debug_abbrev_size;
} DWSections;

DWResult parse_data(AbbrevUnit *entry, DWSections *sections, int data_idx, int attr_idx) {
	uint8_t attr_name = entry->attr_buf[attr_idx];
	uint8_t attr_form = entry->attr_buf[attr_idx + 1];
	uint8_t *debug_info_ptr = sections->debug_info + data_idx;

	DWResult ret = {0};

	switch (attr_form) {
		case DW_FORM_strp: {
			uint32_t str_off = *((uint32_t *)debug_info_ptr);
			char *str = (char *)(sections->debug_str + str_off);


			ret.type = DWString;
			ret.data.str = str;
			ret.skip = sizeof(uint32_t);
		} break;
		case DW_FORM_addr: {
			uint64_t addr = *((uint64_t *)debug_info_ptr);

			ret.type = DWAddr;
			ret.data.val = addr;
			ret.skip = sizeof(uint64_t);
		} break;
		case DW_FORM_data1: {
			uint8_t data = *debug_info_ptr;

			ret.type = DWUVal;
			ret.data.val = data;
			ret.skip = sizeof(uint8_t);
		} break;
		case DW_FORM_data2: {
			uint16_t data = *((uint16_t *)debug_info_ptr);

			ret.type = DWUVal;
			ret.data.val = data;
			ret.skip = sizeof(uint16_t);
		} break;
		case DW_FORM_data4: {
			uint32_t data = *((uint32_t *)debug_info_ptr);

			ret.type = DWUVal;
			ret.data.val = data;
			ret.skip = sizeof(uint32_t);
		} break;
		case DW_FORM_udata: {
			uint32_t leb_size = 0;
			uint64_t udata = get_leb128_u(debug_info_ptr, &leb_size);

			ret.type = DWUVal;
			ret.data.val = udata;
			ret.skip = leb_size;
		} break;
		case DW_FORM_ref4: {
			uint32_t offset = *((uint32_t *)debug_info_ptr);

			ret.type = DWOffset;
			ret.data.val = offset;
			ret.skip = sizeof(uint32_t);
		} break;
		case DW_FORM_sec_offset: {
			uint32_t sect_off = *((uint32_t *)debug_info_ptr);

			ret.type = DWUVal;
			ret.data.val = sect_off;
			ret.skip = sizeof(uint32_t);
		} break;
		case DW_FORM_exprloc: {
			uint32_t leb_size = 0;
			uint64_t length = get_leb128_u(debug_info_ptr, &leb_size);

			ret.type = DWExpr;
			ret.data.expr = debug_info_ptr + leb_size;
			ret.skip = leb_size + length;
			ret.size = length;
		} break;
		case DW_FORM_flag_present: {
			ret.type = DWUVal;
			ret.data.val = 1;
		} break;
		default: {
			printf("(0x%02x) %-18s (0x%02x) %s\n", attr_name, dwarf_attr_name_to_str(attr_name), attr_form, dwarf_attr_form_to_str(attr_form));
			panic("Unhandled form: (0x%02x) %s!\n", attr_form, dwarf_attr_form_to_str(attr_form));
		}
	}

	return ret;
}

typedef struct {
	uint8_t *expr;
	uint64_t len;
} DWExpression;

typedef struct {
	DWType type;
	uint64_t data;
} DWStackVal;

#define VAL_STACK_MAX 1024
typedef struct {
	uint64_t val_stack[VAL_STACK_MAX];
	int val_stack_len;

	Block *frame_holder;
} DWExprMachine;

void eval_expr(struct user_regs_struct *regs, DWExprMachine *em, DWExpression in_ex, int depth) {
	for (uint64_t i = 0; i < in_ex.len; i++) {
		uint8_t op = in_ex.expr[i];

		printf("[%d] 0x%x %s\n", depth, op, dwarf_expr_op_to_str(op));
		if (op >= 0x50 && op <= 0x6f) {
			em->val_stack[em->val_stack_len++] = get_regval_for_dwarf_reg(regs, op - 0x50);
		} else {
			switch (op) {
				case DW_OP_fbreg: {
					uint32_t leb_size = 0;
					int64_t data = get_leb128_i(in_ex.expr + i + 1, &leb_size);

					DWExpression frame_holder_ex = { em->frame_holder->frame_base_expr, em->frame_holder->frame_base_expr_len };
					eval_expr(regs, em, frame_holder_ex, depth + 1);

					em->val_stack_len--;
					em->val_stack[em->val_stack_len] = ((int64_t)em->val_stack[em->val_stack_len]) + data;

					i += leb_size;
				} break;
				default: {
					panic("Unhandled op 0x%x, %s!\n", op, dwarf_expr_op_to_str(op));
				}
			}
		}
	}
}

int main(int argc, char **argv) {
	if (argc < 2) {
		panic("Please provide the debugger a program to debug!\n");
	}

	char cur_dir[PATH_MAX + 1];
	if (getcwd(cur_dir, sizeof(cur_dir)) == NULL) {
		panic("Failed to get current dir!\n");
	}

	char *bin_name = malloc(PATH_MAX + 1);
	bin_name[PATH_MAX] = '\0';

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

	DWSections sections = {0};

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
			sections.debug_info_size = sect_hdr->sh_size;
			sections.debug_info = buffer + sect_hdr->sh_offset;
		} else if (!(strncmp(section_name, dbgabbrev_str, sizeof(dbgabbrev_str)))) {
			sections.debug_abbrev_size = sect_hdr->sh_size;
			sections.debug_abbrev = buffer + sect_hdr->sh_offset;
		} else if (!(strncmp(section_name, dbgstr_str, sizeof(dbgstr_str)))) {
			sections.debug_str_size = sect_hdr->sh_size;
			sections.debug_str = buffer + sect_hdr->sh_offset;
		} else if (!(strncmp(section_name, dbgline_str, sizeof(dbgline_str)))) {
			sections.debug_line_size = sect_hdr->sh_size;
			sections.debug_line = buffer + sect_hdr->sh_offset;
		}
	}

	if (!(sections.debug_info && sections.debug_abbrev && sections.debug_line)) {
		panic("TODO Currently this debugger only supports binaries with debug symbols!\n");
	}

	printf("Building the abbreviation table\n");

	#define ABBREV_MAX 1024
	int abbrev_len = 0;
	AbbrevUnit abbrev_entries[ABBREV_MAX] = {0};
	uint64_t cu_idx = 0;

	int i = 0;
	while (i < sections.debug_abbrev_size) {
		uint32_t leb_size = 0;
		uint64_t abbrev_code = get_leb128_u(sections.debug_abbrev + i, &leb_size);

		i += leb_size;
		if (abbrev_code == 0) {
			cu_idx++;
			continue;
		}

		if (abbrev_len + 1 > ABBREV_MAX) {
			panic("TODO This should probably be dynamic!\n");
		}

		AbbrevUnit *entry = &abbrev_entries[abbrev_len++];
		entry->id = abbrev_code;
		entry->cu_idx = cu_idx;

		leb_size = 0;
		entry->type = get_leb128_u(sections.debug_abbrev + i, &leb_size);
		i += leb_size;

		entry->has_children = sections.debug_abbrev[i];
		i += 1;

		entry->attr_buf = sections.debug_abbrev + i;

		int attr_count = 0;
		while (i < sections.debug_abbrev_size) {
			uint8_t attr_name = sections.debug_abbrev[i + 0];
			uint8_t attr_form = sections.debug_abbrev[i + 1];

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

	#define BLOCK_STACK_MAX 20
	int entry_stack[BLOCK_STACK_MAX] = {0};

	#define BLOCK_MAX 1024
	Block block_table[BLOCK_MAX] = {0};

	uint64_t cur_cu_count = 0;
	uint64_t cur_cu_idx = 0;
	int blk_len = 0;

	i = 0;
	while (i < sections.debug_info_size) {
		DWARF32_CUHdr *cu_hdr = (DWARF32_CUHdr *)(sections.debug_info + i);

		if ((*(uint32_t *)sections.debug_info) == 0xFFFFFFFF) {
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
			uint32_t leb_size = 0;
			uint64_t abbrev_id = get_leb128_u(sections.debug_info + i, &leb_size);
			i += leb_size;

			if (abbrev_id == 0) {
				child_level--;
				continue;
			}

			AbbrevUnit *entry = NULL;
			int cur_au = 0;
			for (; cur_au < abbrev_len; cur_au++) {
				AbbrevUnit *tmp = &abbrev_entries[cur_au];
				if (tmp->id == abbrev_id && tmp->cu_idx == cur_cu_count) {
					entry = tmp;
					break;
				}
			}
			if (!entry) {
				panic("Unable to find abbrev_table entry %lu\n", abbrev_id);
			}

			
			if (entry->type == DW_TAG_compile_unit) {
				cur_cu_idx = blk_len;
			}

			printf("Abbrev %lu -- %s\n", abbrev_id, dwarf_tag_to_str(entry->type));

			Block *blk = &block_table[blk_len++];
			blk->au_offset = i - 1;
			blk->has_children = entry->has_children;
			blk->type = entry->type;
			blk->attr_buf = entry->attr_buf;
			blk->attr_count = entry->attr_count;
			blk->cu_idx = cur_cu_idx;
			blk->au_idx = cur_au;

			if (entry->has_children) {
				child_level++;
			}

			printf("setting estack @ %d to %d\n", child_level, blk_len);
			entry_stack[child_level] = blk_len;

			if (child_level > 0) {
				int parent_idx = entry_stack[child_level - 1];
				printf("settng block %d, parent %d\n", blk_len, parent_idx);
				if (blk_len != parent_idx) {
					blk->parent_idx = parent_idx;
				}
			}

			printf("[0x%lx] Abbrev %d | %lu: (%s) [%s]\n", (uint64_t)blk->au_offset, blk_len, abbrev_id, dwarf_tag_to_str(entry->type), ((entry->has_children) ? "has children" : "no children"));
			for (int j = 0; j < (entry->attr_count * 2); j += 2) {
				uint8_t attr_name = entry->attr_buf[j];
				uint8_t attr_form = entry->attr_buf[j + 1];

				printf("<0x%x> (0x%02x) %-18s (0x%02x) %s\n", i, attr_name, dwarf_attr_name_to_str(attr_name), attr_form, dwarf_attr_form_to_str(attr_form));
				DWResult ret = parse_data(entry, &sections, i, j);

				switch (attr_name) {
					case DW_AT_frame_base: {
						blk->frame_base_expr = ret.data.expr;
						blk->frame_base_expr_len = ret.size;
					} break;
					case DW_AT_low_pc: {
						blk->low_pc = ret.data.val;
					} break;
					case DW_AT_high_pc: {
						blk->high_pc = ret.data.val;
					} break;
					case DW_AT_name: {
						blk->name = ret.data.str;
					} break;
					case DW_AT_type: {
						blk->type_offset = (uint32_t)ret.data.val;
					} break;
					case DW_AT_language: {
						if (ret.data.val != 0x0c) {
							panic("Debugger currently only supports C99, got %lu!\n", ret.data.val);
						}
					} break;
					case DW_AT_location: {
						if (ret.type != DWExpr) {
							panic("Unable to handle static locations!\n");
						}

						blk->loc_expr = ret.data.expr;
						blk->loc_expr_len = ret.size;
					} break;
					default: { 
					}
				}

				i += ret.skip;
			}

			printf("\n");
		} while (i < sections.debug_info_size && child_level > 0);

		cur_cu_count += 1;
	}

	#define LINE_TABLES_MAX 20
	int line_tables_len = 0;
	CULineTable *line_tables = malloc(sizeof(CULineTable) * LINE_TABLES_MAX);

	printf("Parsing .debug_line\n");
	i = 0;
	while (i < sections.debug_line_size) {
		DWARF32_LineHdr *line_hdr = (DWARF32_LineHdr *)(sections.debug_line + i);
		if ((*(uint32_t *)(sections.debug_line + i)) == 0xFFFFFFFF) {
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
		while (i < sections.debug_line_size) {
			char *dirname = (char *)(sections.debug_line + i);
			line_table->dirs[dir_count] = dirname;

			int dirname_length = strnlen(dirname, sections.debug_line_size - i);
			i += dirname_length + 1;
			if (dirname_length == 0) {
				break;
			}

			dir_count++;
		}

		int file_count = 1;
		while (i < sections.debug_line_size) {
			char *filename = (char *)(sections.debug_line + i);

			int filename_length = strnlen(filename, sections.debug_line_size - i);
			i += filename_length + 1;
			if (filename_length == 0) {
				break;
			}

			uint32_t leb_size = 0;
			uint64_t dir_idx = get_leb128_u(sections.debug_line + i, &leb_size);
			i += leb_size;

			leb_size = 0;
			get_leb128_u(sections.debug_line + i, &leb_size); // last modified
			i += leb_size;

			leb_size = 0;
			get_leb128_u(sections.debug_line + i, &leb_size); // file size
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
		line_table->op_buf      = sections.debug_line + i;
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

	//ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[0]), (void *)0x7fffffffd7a8);

	uint64_t orig_data = inject_breakpoint_at_addr(pid, break_addr);
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait(&status);
	if (WIFEXITED(status)) {
		panic("Bailed before reaching main?\n");
	}

	uint64_t trap_rip_cache = break_addr;
	for (;;) {
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		uint64_t trap_inst = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rip - 1, NULL);
		uint64_t cur_inst = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rip, NULL);

		// check if we just stepped over a trap that needs to be patched
		if (((regs.rip - 1) == break_addr) && (trap_inst & 0xFF) == 0xCC && trap_rip_cache != regs.rip) {
			printf("just hit a trap @ %lx\n", break_addr);
			
			// prevent infinitely trapping on the instruction we just trapped
			trap_rip_cache = regs.rip;
			printf("Patching up breakpoint\n");

			repair_breakpoint(pid, break_addr, orig_data);
			regs.rip -= 1;
			ptrace(PTRACE_SETREGS, pid, NULL, &regs);
			uint64_t new_inst = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rip, NULL);
			printf("fixed instruction: %lx\n", new_inst);

			ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

			wait(&status);
			if (WIFEXITED(status)) {
				return 0;
			}

			orig_data = inject_breakpoint_at_addr(pid, break_addr);
			printf("Breakpoint restored\n");
		} else {
			trap_rip_cache = 0;
			ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

			wait(&status);
			if (WIFEXITED(status)) {
				return 0;
			}
		}

		// Dump new regs
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		uint64_t debug_1 = ptrace(PTRACE_PEEKUSER, pid, (void *)offsetof(struct user, u_debugreg[0]), NULL);
		uint64_t stack_top = ptrace(PTRACE_PEEKDATA, pid, (void *)regs.rsp, NULL);

		printf("RIP: %llx\n", regs.rip);
/*
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
		printf("Top of stack: 0x%lx\n", stack_top);
		printf("debug 1: %lx\n", debug_1);
		printf("\n");
*/

/*
 * 	 This gnarly code determines these pieces of 
 * 	 critical information to figure out variable
 * 	 and current scope context from RIP via block_table
 *
 *   framed_scope_block -- contains frame_base_expr
 *   	scope_block -- may only contain high/low pc
 *   		<undefined>
 *   			<undefined>
 *   			var_block -- contains location expr
 */
		char *break_name = "ret";

		// Find current scope based on RIP
		int blk_idx = blk_len - 1;
		Block *scope_block = NULL;
		for (; blk_idx >= 0; blk_idx--) {
			Block *blk = &block_table[blk_idx];
			if ((regs.rip >= blk->low_pc) && (regs.rip <= (blk->low_pc + blk->high_pc))) {
				scope_block = blk;
				break;
			}
		}
		if (scope_block == NULL) {
			goto loop_end;
		}

		// Find nearest named parent scope based on RIP
		Block *framed_scope = NULL;
		if (scope_block->name == NULL) {
			for (int i = blk_len - 1; i >= 0; i--) {
				Block *blk = &block_table[i];
				if (blk->frame_base_expr_len && blk->name != NULL && (regs.rip >= blk->low_pc) && (regs.rip <= (blk->low_pc + blk->high_pc))) {
					framed_scope = blk;
					break;
				}
			}
			if (framed_scope == NULL) {
				goto loop_end;
			}
		} else {
			framed_scope = scope_block;
		}

		// Find variable in scope by descending tree from scope_block (can pass into other scopes)
		Block *var_block = NULL;
		for (; blk_idx < blk_len; blk_idx++) {
			Block *blk = &block_table[blk_idx];
			if (blk->name && strcmp(blk->name, break_name) == 0) {
				var_block = blk;
				break;
			}
		}
		if (var_block == NULL) {
			goto loop_end;
		}

		// Walk parent_idx to confirm that variable obtained in last pass belongs to current scope
		Block *tmp_var_block = var_block;
		for (;;) {
			if (scope_block->idx == tmp_var_block->idx) {
				break;
			}

			if (!tmp_var_block->parent_idx) {
				printf("hit scope max, %s\n", tmp_var_block->name);
				goto loop_end;
			}

			int var_block_idx = tmp_var_block->parent_idx;
			if (!var_block_idx) {
				panic("Unable to lookup parent of entry!\n");
			}

			tmp_var_block = &block_table[var_block_idx];
		}

		printf("Found variable %s in %s\n", var_block->name, framed_scope->name);

		// Start evaluating variable location expression using framed scope as reference
		printf("RIP: %llx, LOW: %lx, HIGH: %lx\n", regs.rip, framed_scope->low_pc, framed_scope->low_pc + framed_scope->high_pc);
		DWExprMachine em = {0};
		em.frame_holder = framed_scope;
		DWExpression ex = { .expr = var_block->loc_expr, .len = var_block->loc_expr_len };
		eval_expr(&regs, &em, ex, 0);

		uint64_t var_addr = em.val_stack[0];
		uint64_t val = ptrace(PTRACE_PEEKDATA, pid, (void *)var_addr, NULL);
		printf("Variable %s in %s @ 0x%lx; %ld\n", var_block->name, framed_scope->name, var_addr, val);
		for (int i = 0; i < em.val_stack_len; i++) {
			printf("val in stack: 0x%lx\n", em.val_stack[i]);
		}

		printf("Function %s in CU %lu\n", framed_scope->name, framed_scope->cu_idx);

		// Determine type of variable
		Block *type_blk = NULL;
		for (int i = 0; i < blk_len; i++) {
			if (block_table[i].au_offset == var_block->type_offset) {
				type_blk = &block_table[i];
				break;
			}
		}
		if (!type_blk) {
			panic("Unable to find type block for function %s\n", framed_scope->name);
		}

		AbbrevUnit type_au = abbrev_entries[type_blk->au_idx];

		int type_width = 0;
		int i = type_blk->au_offset;
		for (int j = 0; j < (type_blk->attr_count * 2); j += 2) {
			uint8_t attr_name = type_blk->attr_buf[j];
			//uint8_t attr_form = type_blk->attr_buf[j + 1];

			DWResult ret = parse_data(&type_au, &sections, i + 1, j);
			switch (attr_name) {
				case DW_AT_name: {
					printf("Type is %s\n", ret.data.str);
				} break;
				case DW_AT_encoding: {
					printf("Encoding is %lu\n", ret.data.val);
				} break;
				case DW_AT_byte_size: {
					printf("Byte size is %lu\n", ret.data.val);
					type_width = ret.data.val;
				} break;
			}

			i += ret.skip;
		}

		// Determine variable address alignment to figure out how to place variable
		int is_8b_aligned = (var_addr & 0x7) == 0;
		int is_4b_aligned = (var_addr & 0x3) == 0;
		int is_2b_aligned = (var_addr & 0x1) == 0;

		if (!(is_8b_aligned || is_4b_aligned || is_2b_aligned || type_width == 1)) {
			panic("Unable to handle unaligned watchpoints!\n");
		}

		char width_bits = 0;
		if (type_width == 8) { width_bits = 0b11; }
		else if (type_width == 4) { width_bits = 0b10; }
		else if (type_width == 2) { width_bits = 0b01; }
		else if (type_width == 1) { width_bits = 0b00; }

		// trap with breakpoint 0, R/W
		uint64_t dr7 = 0b00000000000000110000000000000001;
		dr7 |= (width_bits << 18);

		ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[0]), (void *)var_addr);
		ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[7]), (void *)dr7);
		ptrace(PTRACE_CONT, pid, NULL, NULL);

		int status;
		wait(&status);
		if (!WIFSTOPPED(status)) {
			panic("Failure to break on breakpoint\n");
		}

		uint64_t new_val = ptrace(PTRACE_PEEKDATA, pid, (void *)var_addr, NULL);
		printf("CHANGE DETECTED: Variable %s in %s @ 0x%lx; %ld\n", var_block->name, framed_scope->name, var_addr, new_val);

loop_end:
		usleep(500000);
	}
}
