#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/personality.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * Handy References:
 * - https://refspecs.linuxbase.org/elf/elf.pdf
 * - http://man7.org/linux/man-pages/man5/elf.5.html
 * - http://dwarfstd.org/doc/DWARF4.pdf
 * - https://wiki.osdev.org/DWARF
 */

// MACROS
#define panic(...) do { dprintf(2, __VA_ARGS__); exit(1); } while (0)
#define assert(x, ...) do { if ((x)) { dprintf(2, __VA_ARGS__); exit(1); } } while (0)
#define happy_death(...) do { dprintf(2, __VA_ARGS__); exit(0); } while (0)

// GLOBALS
#define HW_SLOTS_MAX 4
#define BLOCK_STACK_MAX 20
#define LINE_TABLES_MAX 20
#define TYPE_CHAIN_MAX 20
#define MEMBERS_MAX 30
#define VAL_STACK_MAX 32
#define BREAKPOINTS_MAX 1024
#define WATCHPOINTS_MAX 1024
#define LINE_BUFFER_MAX 1024
#define BLOCK_MAX 1024
#define ABBREV_MAX 1024
#define OUTBUF_MAX 4096

// DEFINES
#define DT_NULL 0
#define DT_NEEDED 1
#define DT_STRTAB 5
#define DT_SYMTAB 6

enum {
	SHT_NULL = 0,
	SHT_PROGBITS,
	SHT_SYMTAB,
	SHT_STRTAB,
	SHT_RELA,
	SHT_HASH,
	SHT_DYNAMIC
};

typedef struct {
	uint8_t *data;
	uint64_t offset;
	uint64_t length;
} dol_t;

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
	uint64_t tag;
	uint64_t val;
} ELF64_Dyn;

typedef struct {
	uint32_t unit_length;
	uint16_t version;
	uint32_t debug_abbrev_offset;
	uint8_t  address_size;
} DWARF32_CUHdr;

typedef struct {
	uint8_t  min_inst_length;
	uint8_t  max_ops_per_inst;
	uint8_t  default_is_stmt;
	int8_t   line_base;
	uint8_t  line_range;
	uint8_t  opcode_base;
} DWARF_V4_LineHdr;

typedef struct {
	uint8_t  min_inst_length;
	uint8_t  default_is_stmt;
	int8_t   line_base;
	uint8_t  line_range;
	uint8_t  opcode_base;
} DWARF_V3_LineHdr;
#pragma pack()

typedef struct {
	uint8_t  min_inst_length;
	uint8_t  max_ops_per_inst;
	uint8_t  default_is_stmt;
	int8_t   line_base;
	uint8_t  line_range;
	uint8_t  opcode_base;
} DWARF_LineHdr;

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
	int depth;

	uint64_t parent_idx;
	uint64_t cu_idx;

	uint8_t *attr_buf;
	int      attr_count;

	uint32_t type;
	uint64_t type_idx;
	uint64_t au_offset;
	uint64_t type_offset;

	char *name;
	char *comp_dir;

	uint8_t *loc_expr;
	int loc_expr_len;
	uint8_t *loc_list;
	uint64_t const_val;

	uint8_t *frame_base_expr;
	int frame_base_expr_len;

	uint32_t type_width;
	uint32_t type_encoding;

	uint32_t member_offset;
	bool member_offset_present;

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
	uint8_t   line_range;
	uint8_t  opcode_base;

	LineMachine *lines;
	int line_count;
	int line_max;
} CULineTable;

typedef struct {
	uint64_t address;
	uint64_t orig_data;
	uint64_t ref_count;
} Breakpoint;

typedef struct {
	uint8_t *old_data;
	uint8_t *new_data;

	uint64_t member_idx;
	uint64_t member_offset;

	uint64_t watch_width;
	uint64_t end;

	// Block idx
	uint64_t var_idx;

	// Breakpoint idx
	uint64_t break_idx;
} Watchpoint;

typedef enum {
	HWNone = 0x0,
	HWBreakpoint,
	HWWatchpoint,
} HWBreakType;

typedef struct {
	uint64_t addr;

	uint64_t idx;
	HWBreakType type;
} HWBreak;


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
	uint64_t var_idx;
	uint64_t width;

	uint64_t member_idx;
	uint64_t member_offset;
} VarInfo;

typedef struct {
	uint8_t *file_buffer;
	uint64_t file_size;

	char *bin_name;
	char **args;
	char cur_dir[PATH_MAX + 1];

	uint8_t *strtab;
	int strtab_size;

	uint8_t *dynamic;
	int dynamic_size;

	uint8_t *dynstr;
	int dynstr_size;

	uint8_t *debug_info;
	int debug_info_size;

	uint8_t *debug_line;
	int debug_line_size;

	uint8_t *debug_str;
	int debug_str_size;

	uint8_t *debug_abbrev;
	int debug_abbrev_size;

	uint8_t *debug_loc;
	int debug_loc_size;
} DWSections;

typedef struct {
	uint8_t *expr;
	uint64_t len;
} DWExpression;

typedef struct {
	uint64_t val_stack[VAL_STACK_MAX];
	uint64_t val_stack_len;

	Block *frame_holder;
} DWExprMachine;

typedef struct {
	uint64_t start;
	uint64_t end;
} FuncFrame;

typedef struct {
	uint64_t framed_scope_idx;
	uint64_t scope_idx;
} CurrentScopes;

typedef struct {
	DWSections sections;

	Block *block_table;
	uint64_t block_len;
	uint64_t block_max;

	CULineTable *line_tables;
	uint64_t line_tables_len;
	uint64_t line_tables_max;

	Breakpoint *break_table;
	uint64_t break_len;
	uint64_t break_max;

	Watchpoint *watch_table;
	uint64_t watch_len;
	uint64_t watch_max;

	bool needs_restart;

	bool should_reset;
	uint64_t reset_idx;

	bool sw_watch_enabled;
	HWBreak hw_slots[HW_SLOTS_MAX];
	uint64_t hw_slots_max;
} DebugState;

#define DWARF_FORM \
	X(DW_FORM_addr,   0x01) \
	X(DW_FORM_block2, 0x03) \
	X(DW_FORM_block4, 0x04) \
	X(DW_FORM_data2,  0x05) \
	X(DW_FORM_data4,  0x06) \
	X(DW_FORM_data8,  0x07) \
	X(DW_FORM_string, 0x08) \
	X(DW_FORM_block,  0x09) \
	X(DW_FORM_block1, 0x0a) \
	X(DW_FORM_data1,  0x0b) \
	X(DW_FORM_flag,   0x0c) \
	X(DW_FORM_sdata,  0x0d) \
	X(DW_FORM_strp,   0x0e) \
	X(DW_FORM_udata,  0x0f) \
	X(DW_FORM_ref_addr,  0x10) \
	X(DW_FORM_ref1,   0x11) \
	X(DW_FORM_ref2,   0x12) \
	X(DW_FORM_ref4,   0x13) \
	X(DW_FORM_ref8,   0x14) \
	X(DW_FORM_ref_udata,  0x15) \
	X(DW_FORM_indirect,   0x16) \
	X(DW_FORM_sec_offset, 0x17) \
	X(DW_FORM_exprloc,    0x18) \
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
	X(DW_TAG_program, 0xFF) \

#define DWARF_ATE \
	X(DW_ATE_address, 0x01) \
	X(DW_ATE_boolean, 0x02) \
	X(DW_ATE_complex_float, 0x03) \
	X(DW_ATE_float, 0x04) \
	X(DW_ATE_signed, 0x05) \
	X(DW_ATE_signed_char, 0x06) \
	X(DW_ATE_unsigned, 0x07) \
	X(DW_ATE_unsigned_char, 0x08) \
	X(DW_ATE_imaginary_float, 0x09) \
	X(DW_ATE_packed_decimal, 0x0a) \
	X(DW_ATE_numeric_string, 0x0b) \
	X(DW_ATE_edited, 0x0c) \
	X(DW_ATE_signed_fixed, 0x0d) \
	X(DW_ATE_unsigned_fixed, 0x0e) \
	X(DW_ATE_decimal_float, 0x0f) \
	X(DW_ATE_UTF, 0x10) \
	X(DW_ATE_lo_user, 0x80) \
	X(DW_ATE_hi_user, 0xff) \

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
enum { DWARF_ATE };
enum { DWARF_LINE };
enum { DWARF_LNS };
enum { DWARF_OP };
#undef X


uint64_t get_regval_for_dwarf_reg(struct user_regs_struct *regs, uint8_t idx) {
	switch (idx) {
		case 0: return regs->rax;
		case 1: return regs->rdx;
		case 2: return regs->rcx;
		case 3: return regs->rbx;
		case 4: return regs->rsi;
		case 5: return regs->rdi;
		case 6: return regs->rbp;
		case 7: return regs->rsp;
		case 8: return regs->r8;
		case 9: return regs->r9;
		case 10: return regs->r10;
		case 11: return regs->r11;
		case 12: return regs->r12;
		case 13: return regs->r13;
		case 14: return regs->r14;
		case 15: return regs->r15;
//		case 16: return regs->ra;
/*
		case 17: return regs->xmm0;
		case 18: return regs->xmm1;
		case 19: return regs->xmm2;
		case 20: return regs->xmm3;
		case 21: return regs->xmm4;
		case 22: return regs->xmm5;
		case 23: return regs->xmm6;
		case 24: return regs->xmm7;
		case 25: return regs->xmm8;
		case 26: return regs->xmm9;
		case 27: return regs->xmm10;
		case 28: return regs->xmm11;
		case 29: return regs->xmm12;
		case 30: return regs->xmm13;
		case 31: return regs->xmm14;
		case 32: return regs->xmm15;
*/
	}	
	return 0;
}

uint64_t get_time_ms() {
    struct timespec tms;
	clock_gettime(CLOCK_MONOTONIC, &tms);

	uint64_t millis = tms.tv_sec * 1000;
	millis += tms.tv_nsec / 1000000;
	return millis;
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
		case 0: return "0";
		#define X(name, value) case name: return #name;
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

char *dwarf_type_to_str(uint8_t type) {
	switch (type) {
		#define X(name, value) case name: return #name;
			DWARF_ATE
		#undef X
		default:   {
			return "(unknown)";
		}
	}
}

char *dwarf_attr_name_to_str(uint8_t attr_name) {
	switch (attr_name) {
		case 0: return "0";
		#define X(name, value) case name: return #name;
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
		case 0: return "0";
		#define X(name, value) case name: return #name;
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
		#define X(name, value) case name: return #name;
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
		#define X(name, value) case name: return #name;
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
	static char op_str_cache[20];

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
		#define X(name, value) case name: return #name;
			DWARF_OP
		#undef X
		default: return "(unknown)";
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

void print_line_table(CULineTable *line_tables, uint64_t line_tables_len) {
	for (uint64_t i = 0; i < line_tables_len; i++) {
		CULineTable *line_table = &line_tables[i];
		printf("CU Line Table %lu\n", i + 1);
		printf("Files:\n");
		for (int j = 0; j < line_table->file_count; j++) {
			uint8_t dir_idx = line_table->dir_idx[j];
			char *dirname = line_table->dirs[dir_idx];
			if (!line_table->filenames[j]) {
				continue;
			}

			printf("[%d] - %s | %s\n", j, dirname, line_table->filenames[j]);
		}
/*
		for (int j = 0; j < line_table->line_count; j++) {
			LineMachine *line = &line_table->lines[j];
			printf("line %u | address 0x%lx | file %s\n", 
				line->line_num, line->address, line_table->filenames[line->file_idx]);
		}
*/
		printf("opcode base: %d\n", line_table->opcode_base);
		printf("line base: %d\n", line_table->line_base);
		printf("line range: %d\n", line_table->line_range);
		printf("default is_stmt: %d\n", line_table->default_is_stmt);
		printf("\n");
	}
}

void print_block_table(Block *block_table, uint64_t block_len) {
	for (uint64_t i = 0; i < block_len; i++) {
		Block *block = &block_table[i];
		int indent_width = block->depth * 4;
		printf("%*c<0x%lx> [%lu] %s\n", indent_width, ' ', block->au_offset, i, dwarf_tag_to_str(block->type));

		if (block->name) {
			printf("%*c- name: %s\n", indent_width, ' ',  block->name);
		}
		if (block->comp_dir) {
			printf("%*c- path: %s/%s\n", indent_width, ' ',  block->comp_dir, block->name);
		}
		if (block->low_pc && block->high_pc) {
			printf("%*c- range: 0x%lx - 0x%lx\n", indent_width, ' ',  block->low_pc, block->high_pc + block->low_pc);
		}
		if (block->frame_base_expr && block->frame_base_expr_len) {
			printf("%*c- frame base expr: ", indent_width, ' ');
			for (int j = 0; j < block->frame_base_expr_len; j++) {
				printf("%x ", block->frame_base_expr[j]);
			}
			printf("\n");
		}
		if (block->loc_expr && block->loc_expr_len) {
			printf("%*c- location expr: ", indent_width, ' ');
			for (int j = 0; j < block->loc_expr_len; j++) {
				printf("%x ", block->loc_expr[j]);
			}
			printf("\n");
		}
		if (block->type_offset) {
			printf("%*c- type offset: <0x%lx>\n", indent_width, ' ', block->type_offset);
		}
		if (block->member_offset_present) {
			printf("%*c- member offset: <0x%x>\n", indent_width, ' ', block->member_offset);
		}
		if (block->type_width) {
			printf("%*c- type width: %u\n", indent_width, ' ', block->type_width);
		}
		if (block->type_encoding) {
			printf("%*c- type encoding: %s\n", indent_width, ' ', dwarf_type_to_str(block->type_encoding));
		}
	}
}

int open_binary(char *name, char **prog_path) {
	int fd;

	fd = open(name, O_RDONLY);
	if (fd >= 0) {
		strcpy(*prog_path, name);
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

DWResult parse_data(DWSections *sections, int data_idx, uint8_t *attr_elem) {
	uint64_t entry_size = 0;
	uint32_t leb_size = 0;
	uint64_t attr_name = get_leb128_u(attr_elem, &leb_size);
	if (!leb_size) {
		panic("failed to parse leb!\n");
	}
	entry_size += leb_size;

	leb_size = 0;
	uint64_t attr_form = get_leb128_u(attr_elem + entry_size, &leb_size);
	if (!leb_size) {
		panic("failed to parse leb!\n");
	}

	uint8_t *debug_info_ptr = sections->debug_info + data_idx;
	DWResult ret = {0};

	switch (attr_form) {
		case DW_FORM_string: {
			char *str = (char *)debug_info_ptr;
			uint64_t str_len = strlen(str);

			ret.type = DWString;
			ret.data.str = str;
			ret.skip = str_len + 1;
		} break;
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
		case DW_FORM_sdata: {
			uint32_t leb_size = 0;
			uint64_t sdata = get_leb128_i(debug_info_ptr, &leb_size);

			ret.type = DWIVal;
			ret.data.val = sdata;
			ret.skip = leb_size;
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
			printf("(0x%02lx) %-18s (0x%02lx) %s\n", attr_name, dwarf_attr_name_to_str(attr_name), attr_form, dwarf_attr_form_to_str(attr_form));
			panic("Unhandled form: (0x%02lx) %s!\n", attr_form, dwarf_attr_form_to_str(attr_form));
		}
	}

	return ret;
}

uint64_t get_file_size(int fd) {
	off_t f_end = lseek(fd, 0, SEEK_END);
	if (f_end < 0) {
		panic("Failed to seek to end of file!\n");
	}
	lseek(fd, 0, SEEK_SET);

	return f_end;
}

void load_elf_sections(DWSections *sections, char *file_path) {
	if (getcwd(sections->cur_dir, sizeof(sections->cur_dir)) == NULL) {
		panic("Failed to get current dir!\n");
	}

	sections->bin_name = malloc(PATH_MAX + 1);
	sections->bin_name[PATH_MAX] = '\0';

	int fd = open_binary(file_path, &sections->bin_name);
	if (fd < 0) {
		panic("Failed to open program %s\n", file_path);
	}

	printf("Debugging %s\n", sections->bin_name);

	uint64_t size = get_file_size(fd);
	sections->file_buffer = malloc(size);
	sections->file_size = size;

	ssize_t ret = read(fd, sections->file_buffer, size);
	if (ret < 0 || (uint64_t)ret != size) {
		panic("Failed to read %s\n", sections->bin_name);
	}
	close(fd);

	Elf64_Ehdr *elf_hdr = (Elf64_Ehdr *)sections->file_buffer;
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
	#define ET_CORE  4

	if (elf_hdr->e_type == ET_CORE) {
		panic("This debugger doesn't support core dumps yet!\n");
	}

	if (!(elf_hdr->e_type == ET_EXEC || elf_hdr->e_type == ET_DYN)) {
		panic("This debugger only supports executable files\n");
	}

	if (!elf_hdr->e_shstrndx) {
		panic("TODO This debugger requires symbols to be able to debug the file\n");
	}

	uint8_t *sect_hdr_buf = sections->file_buffer + elf_hdr->e_shoff;
	ELF64_Shdr *strtable_hdr = (ELF64_Shdr *)(sect_hdr_buf + (elf_hdr->e_shstrndx * elf_hdr->e_shentsize));
	if (strtable_hdr->sh_type != SHT_STRTAB) {
		panic("Executable string table appears invalid!\n");
	}

	char *strtable = (char *)(sections->file_buffer + strtable_hdr->sh_offset);
	for (int i = 0; i < elf_hdr->e_shnum; i++) {
		ELF64_Shdr *sect_hdr = (ELF64_Shdr *)(sect_hdr_buf + (i * elf_hdr->e_shentsize));

		char *section_name = strtable + sect_hdr->sh_name;

		char dbginfo_str[] = ".debug_info";
		char dbgabbrev_str[] = ".debug_abbrev";
		char dbgstr_str[] = ".debug_str";
		char dbgline_str[] = ".debug_line";
		char dbgloc_str[] = ".debug_loc";
		char dynamic_str[] = ".dynamic";
		char dynstr_str[] = ".dynstr";
		char strtab_str[] = ".strtab";

		if (!(memcmp(section_name, dbginfo_str, sizeof(dbginfo_str)))) {
			sections->debug_info_size = sect_hdr->sh_size;
			sections->debug_info = sections->file_buffer + sect_hdr->sh_offset;
		} else if (!(memcmp(section_name, dbgabbrev_str, sizeof(dbgabbrev_str)))) {
			sections->debug_abbrev_size = sect_hdr->sh_size;
			sections->debug_abbrev = sections->file_buffer + sect_hdr->sh_offset;
		} else if (!(memcmp(section_name, dbgstr_str, sizeof(dbgstr_str)))) {
			sections->debug_str_size = sect_hdr->sh_size;
			sections->debug_str = sections->file_buffer + sect_hdr->sh_offset;
		} else if (!(memcmp(section_name, dbgline_str, sizeof(dbgline_str)))) {
			sections->debug_line_size = sect_hdr->sh_size;
			sections->debug_line = sections->file_buffer + sect_hdr->sh_offset;
		} else if (!(memcmp(section_name, dynamic_str, sizeof(dynamic_str)))) {
			sections->dynamic_size = sect_hdr->sh_size;
			sections->dynamic = sections->file_buffer + sect_hdr->sh_offset;
		} else if (!(memcmp(section_name, dynstr_str, sizeof(dynstr_str)))) {
			sections->dynstr_size = sect_hdr->sh_size;
			sections->dynstr = sections->file_buffer + sect_hdr->sh_offset;
		} else if (!(memcmp(section_name, strtab_str, sizeof(strtab_str)))) {
			sections->strtab_size = sect_hdr->sh_size;
			sections->strtab = sections->file_buffer + sect_hdr->sh_offset;
		} else if (!(memcmp(section_name, dbgloc_str, sizeof(dbgloc_str)))) {
			sections->debug_loc_size = sect_hdr->sh_size;
			sections->debug_loc = sections->file_buffer + sect_hdr->sh_offset;
		}
	}

	if (!(sections->debug_info && sections->debug_abbrev && sections->debug_line)) {
		panic("TODO Currently this debugger only supports binaries with debug symbols!\n");
	}
}

void get_dynamic_libraries(DWSections *sections) {
	if (!sections->dynamic) {
		panic("TODO ELF does not contain a dynamic section!\n");
	}

	for (int i = 0; i < sections->dynamic_size; i += sizeof(ELF64_Dyn)) {
		ELF64_Dyn *dyn_entry = (ELF64_Dyn *)(sections->dynamic + i);
		if (dyn_entry->tag == DT_NEEDED) {
			printf("NEEDED %s\n", sections->dynstr + dyn_entry->val);
		}
	}
}

void build_block_table(DWSections *sections, Block **ext_block_table, uint64_t *blk_len, uint64_t *block_max) {
	Block *block_table = *ext_block_table;

	int abbrev_len = 0;
	AbbrevUnit abbrev_entries[ABBREV_MAX] = {0};
	uint64_t cu_idx = 0;

	int i = 0;
	while (i < sections->debug_abbrev_size) {
		uint32_t leb_size = 0;
		uint64_t abbrev_code = get_leb128_u(sections->debug_abbrev + i, &leb_size);

		i += leb_size;
		if (abbrev_code == 0) {
			cu_idx++;
			continue;
		}

		if (abbrev_len + 1 > ABBREV_MAX) {
			panic("TODO 1 This should probably be dynamic!\n");
		}

		AbbrevUnit *entry = &abbrev_entries[abbrev_len++];
		entry->id = abbrev_code;
		entry->cu_idx = cu_idx;

		leb_size = 0;
		entry->type = get_leb128_u(sections->debug_abbrev + i, &leb_size);
		i += leb_size;

		entry->has_children = sections->debug_abbrev[i];
		i += 1;

		entry->attr_buf = sections->debug_abbrev + i;

		int attr_count = 0;
		while (i < sections->debug_abbrev_size) {
			uint64_t entry_size = 0;

			leb_size = 0;
			uint64_t attr_name = get_leb128_u(sections->debug_abbrev + i, &leb_size);
			if (!leb_size) {
				panic("failed to parse leb!\n");
			}
			entry_size += leb_size;

			leb_size = 0;
			uint64_t attr_form = get_leb128_u(sections->debug_abbrev + i + entry_size, &leb_size);
			if (!leb_size) {
				panic("failed to parse leb!\n");
			}
			entry_size += leb_size;

			i += entry_size;
			if (attr_name == 0 && attr_form == 0) {
				break;
			}

			attr_count += 1;
		}

		entry->attr_count = attr_count;
	}

	uint64_t entry_stack[BLOCK_STACK_MAX] = {0};
	uint64_t cur_cu_count = 0;
	uint64_t cur_cu_idx = 0;
	uint64_t cur_cu_off = 0;

	// Reserve block 0 as the full program block
	block_table[0].type = DW_TAG_program;
	block_table[0].name = "Program Top";
	entry_stack[0] = 0;
	*blk_len += 1;

	i = 0;
	while (i < sections->debug_info_size) {
		DWARF32_CUHdr *cu_hdr = (DWARF32_CUHdr *)(sections->debug_info + i);

		if ((*(uint32_t *)sections->debug_info) == 0xFFFFFFFF) {
			panic("TODO Currently this debugger only handles 32 bit DWARF!\n");
		}

		if (cu_hdr->unit_length == 0) {
			i += sizeof(cu_hdr->unit_length);
			continue;
		}

		if (!(cu_hdr->version == 4 || cu_hdr->version == 3)) {
			panic("TODO This code supports DWARF 3 and 4, got %d!\n", cu_hdr->version);
		}
		i += sizeof(DWARF32_CUHdr);

		cur_cu_off = i - sizeof(DWARF32_CUHdr);
		cur_cu_idx = *blk_len;

		uint64_t child_level = 1;
		do {
			uint32_t leb_size = 0;
			uint64_t abbrev_id = get_leb128_u(sections->debug_info + i, &leb_size);
			i += leb_size;

			if (abbrev_id == 0) {
				child_level--;
				continue;
			}

			if (*blk_len + 1 > *block_max) {
				uint64_t old_max = *block_max;
				uint64_t old_size = old_max * sizeof(Block);

				*ext_block_table = realloc(*ext_block_table, old_size * 2);
				block_table = *ext_block_table;

				memset(block_table + old_max, 0, old_size);
				*block_max = *block_max * 2;
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

			Block *blk = &block_table[*blk_len];
			blk->au_offset = i - 1;
			blk->has_children = entry->has_children;
			blk->type = entry->type;
			blk->attr_buf = entry->attr_buf;
			blk->attr_count = entry->attr_count;
			blk->cu_idx = cur_cu_idx;
			blk->depth = child_level;

			uint64_t entry_offset = 0;
			for (int j = 0; j < (entry->attr_count * 2); j += 2) {
				uint64_t entry_start = entry_offset;

				uint32_t leb_size = 0;
				uint64_t attr_name = get_leb128_u(entry->attr_buf + entry_offset, &leb_size);
				if (!leb_size) {
					panic("failed to parse leb!\n");
				}
				entry_offset += leb_size;

				uint64_t attr_form = get_leb128_u(entry->attr_buf + entry_offset, &leb_size);
				if (!leb_size) {
					panic("failed to parse leb!\n");
				}
				entry_offset += leb_size;

				DWResult ret = parse_data(sections, i, entry->attr_buf + entry_start);

				switch (attr_name) {
					case DW_AT_data_member_location: {
						if (ret.type != DWUVal) {
							panic("Unable to handle member location exprs\n");
						}

						blk->member_offset = ret.data.val;
						blk->member_offset_present = true;
					} break;
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
						blk->type_offset = (uint32_t)(ret.data.val + cur_cu_off);
					} break;
					case DW_AT_language: {
						if (!(ret.data.val == 0x0c || ret.data.val == 32769)) {
							panic("Debugger currently only supports C99 and x64 ASM, got %lu!\n", ret.data.val);
						}
					} break;
					case DW_AT_location: {
						if (ret.type == DWExpr) {
							blk->loc_expr = ret.data.expr;
							blk->loc_expr_len = ret.size;
						} else if (attr_form == DW_FORM_sec_offset) {
							blk->loc_list = sections->debug_loc + ret.data.val;
						} else {
							panic("Unable to handle static locations!\n");
						}
					} break;
					case DW_AT_byte_size: {
						blk->type_width = ret.data.val;
					} break;
					case DW_AT_encoding: {
						blk->type_encoding = ret.data.val;
					} break;
					case DW_AT_comp_dir: {
						blk->comp_dir = ret.data.str;
					} break;
					case DW_AT_const_value: {
					} break;
					default: { }
				}

				i += ret.skip;
			}

			entry_stack[child_level] = *blk_len;

			uint64_t parent_idx = entry_stack[child_level - 1];
			if (entry->has_children) {
				child_level++;
			}

			if (*blk_len != parent_idx) {
				blk->parent_idx = parent_idx;
			}

			*blk_len += 1;
		} while (i < sections->debug_info_size && child_level > 1);

		cur_cu_count += 1;
	}

	for (uint64_t i = 0; i < *blk_len; i++) {
		Block *b1 = &block_table[i];
		if (!b1->type_offset) {
			continue;
		}

		for (uint64_t j = 0; j < *blk_len; j++) {
			Block *b2 = &block_table[j];
			if (b1->type_offset == b2->au_offset) {
				b1->type_idx = j;
				break;
			}
		}
	}
}

uint64_t parse_dwarfv4_line_hdr(DWARF_LineHdr *line_hdr, dol_t *ptr) {
	if (ptr->offset + sizeof(DWARF_V4_LineHdr) > ptr->length) {
		panic("Not enough space for DWARF line header!\n");
	}

	DWARF_V4_LineHdr *int_line_hdr = (DWARF_V4_LineHdr *)(ptr->data + ptr->offset);
	line_hdr->min_inst_length = int_line_hdr->min_inst_length;
	line_hdr->max_ops_per_inst = int_line_hdr->max_ops_per_inst;
	line_hdr->default_is_stmt = int_line_hdr->default_is_stmt;
	line_hdr->line_base 	  = int_line_hdr->line_base;
	line_hdr->line_range 	  = int_line_hdr->line_range;
	line_hdr->opcode_base 	  = int_line_hdr->opcode_base;

	return sizeof(DWARF_V4_LineHdr);
}

uint64_t parse_dwarfv3_line_hdr(DWARF_LineHdr *line_hdr, dol_t *ptr) {
	if (ptr->offset + sizeof(DWARF_V3_LineHdr) > ptr->length) {
		panic("Not enough space for DWARF line header!\n");
	}

	DWARF_V3_LineHdr *int_line_hdr = (DWARF_V3_LineHdr *)(ptr->data + ptr->offset);
	line_hdr->min_inst_length = int_line_hdr->min_inst_length;
	line_hdr->default_is_stmt = int_line_hdr->default_is_stmt;
	line_hdr->line_base 	  = int_line_hdr->line_base;
	line_hdr->line_range 	  = int_line_hdr->line_range;
	line_hdr->opcode_base 	  = int_line_hdr->opcode_base;

	return sizeof(DWARF_V3_LineHdr);
}

void build_line_tables(DWSections *sections, CULineTable **ext_line_table, uint64_t *line_tables_len, uint64_t *line_tables_max) {
	CULineTable *line_tables = *ext_line_table;

	int i = 0;
	while (i < sections->debug_line_size) {
		uint32_t unit_length = *(uint32_t *)(sections->debug_line + i);
		if (unit_length == 0xFFFFFFFF) {
			panic("TODO Currently this debugger only handles 32 bit DWARF!\n");
		}
		i += sizeof(unit_length);

		if (unit_length == 0) {
			continue;
		}

		uint16_t version = *(uint16_t *)(sections->debug_line + i);
		if (!(version == 4 || version == 3)) {
			panic("TODO This code supports DWARF 3 and 4, got %d!\n", version);
		}
		i += sizeof(version);

		// TODO make this vary to support DWARF64
		uint64_t header_length = *(uint32_t *)(sections->debug_line + i);
		uint32_t header_length_size = sizeof(uint32_t);
		i += header_length_size;

		DWARF_LineHdr line_hdr = {0};
		dol_t ptr = { .data = sections->debug_line, .offset = i, .length = sections->debug_line_size };
		if (version == 3) {
			i += parse_dwarfv3_line_hdr(&line_hdr, &ptr);
		} else if (version == 4) {
			i += parse_dwarfv4_line_hdr(&line_hdr, &ptr);
		}
		
/*
		printf("min inst length:  %d\n", line_hdr.min_inst_length);
		printf("default is stmt:  %d\n", line_hdr.default_is_stmt);
		printf("line base:        %d\n", line_hdr.line_base);
		printf("line range:       %d\n", line_hdr.line_range);
		printf("opcode base:      %d\n", line_hdr.opcode_base);
*/

		if (line_hdr.opcode_base != 13) {
			panic("TODO This debugger can't handle non-standard line ops! %d\n", line_hdr.opcode_base);
		}

		CULineTable *line_table = &line_tables[*line_tables_len];
		if (*line_tables_len + 1 > *line_tables_max) {
			panic("TODO make the line tables properly stretchy!\n");
		}
		*line_tables_len += 1;

		int op_lengths_size = line_hdr.opcode_base - 1;
		i += op_lengths_size;

		line_table->dirs[0] = sections->cur_dir;
		int dir_count = 1;
		while (i < sections->debug_line_size) {
			char *dirname = (char *)(sections->debug_line + i);
			line_table->dirs[dir_count] = dirname;

			int dirname_length = strnlen(dirname, sections->debug_line_size - i);
			i += dirname_length + 1;
			if (dirname_length == 0) {
				break;
			}

			dir_count++;
		}

		int file_count = 1;
		while (i < sections->debug_line_size) {
			char *filename = (char *)(sections->debug_line + i);

			int filename_length = strnlen(filename, sections->debug_line_size - i);
			i += filename_length + 1;
			if (filename_length == 0) {
				break;
			}

			uint32_t leb_size = 0;
			uint64_t dir_idx = get_leb128_u(sections->debug_line + i, &leb_size);
			i += leb_size;

			leb_size = 0;
			get_leb128_u(sections->debug_line + i, &leb_size); // last modified
			i += leb_size;

			leb_size = 0;
			get_leb128_u(sections->debug_line + i, &leb_size); // file size
			i += leb_size;

			line_table->filenames[file_count] = filename;
			line_table->dir_idx[file_count]   = dir_idx;
			file_count++;
		}

		uint32_t cu_size  = unit_length + sizeof(unit_length);
		uint32_t hdr_size = header_length + sizeof(unit_length) + sizeof(version) + header_length_size;
		uint32_t rem_size = cu_size - hdr_size;

		line_table->dir_count   = dir_count;
		line_table->file_count  = file_count;
		line_table->op_buf      = sections->debug_line + i;
		line_table->op_buf_size = rem_size;
		line_table->opcode_base = line_hdr.opcode_base;
		line_table->line_base   = line_hdr.line_base;
		line_table->line_range  = line_hdr.line_range;

		line_table->line_max    = 4096;
		line_table->lines       = calloc(sizeof(LineMachine), line_table->line_max);
		line_table->line_count  = 0;

		i += rem_size;
	}


	// Process Line Ops
	for (uint64_t i = 0; i < *line_tables_len; i++) {
		CULineTable *line_table = &line_tables[i];

		LineMachine lm_state;
		init_line_machine(&lm_state, line_table->default_is_stmt);

		for (uint32_t j = 0; j < line_table->op_buf_size; j++) {
			uint8_t op_byte = *(line_table->op_buf + j);

			if (op_byte >= line_table->opcode_base) {
				uint8_t real_op = op_byte - line_table->opcode_base;

				int line_inc = line_table->line_base + (real_op % line_table->line_range);
				int addr_inc = real_op / line_table->line_range;

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

					j += 2;
					uint8_t real_op = *(line_table->op_buf + j);

					switch (real_op) {
						case DW_LNE_end_sequence: {
							lm_state.end_sequence = true;
							memcpy(&line_table->lines[line_table->line_count++], &lm_state, sizeof(lm_state));
						} break;
						case DW_LNE_set_address: {
							uint64_t address = *(uint64_t *)(line_table->op_buf + j + 1);

							lm_state.address = address;
							j += sizeof(address);

						} break;
						default: {
							panic("Unhandled extended lineVM op! %02x\n", real_op);
						}
					}
				} break;
				case DW_LNS_copy: {
					memcpy(&line_table->lines[line_table->line_count++], &lm_state, sizeof(lm_state));

					lm_state.discriminator  = 0;
					lm_state.basic_block    = false;
					lm_state.prologue_end   = false;
					lm_state.epilogue_begin = false;
				} break;
				case DW_LNS_advance_pc: {
					uint32_t leb_size = 0;
					uint64_t addr_inc = get_leb128_u(line_table->op_buf + j + 1, &leb_size);

					lm_state.address += addr_inc;

					j += leb_size;
				} break;
				case DW_LNS_advance_line: {
					uint32_t leb_size = 0;
					int64_t line_inc = get_leb128_i(line_table->op_buf + j + 1, &leb_size);

					lm_state.line_num += line_inc;

					j += leb_size;
				} break;
				case DW_LNS_set_file: {
					uint32_t leb_size = 0;
					uint64_t file_idx = get_leb128_u(line_table->op_buf + j + 1, &leb_size);

					lm_state.file_idx = file_idx;

					j += leb_size;
				} break;
				case DW_LNS_set_column: {
					uint32_t leb_size = 0;
					uint64_t col_num = get_leb128_u(line_table->op_buf + j + 1, &leb_size);

					lm_state.col_num = col_num;

					j += leb_size;
				} break;
				case DW_LNS_negate_stmt: {
					lm_state.is_stmt = !lm_state.is_stmt;
				} break;
				case DW_LNS_const_add_pc: {
					int addr_inc = (255 - line_table->opcode_base) / line_table->line_range;
					lm_state.address += addr_inc;
				} break;
				case DW_LNS_set_prologue_end: {
					lm_state.prologue_end = true;
				} break;
				default: {
					panic("Unhandled lineVM op! %02x\n", op_byte);
				}
			}
		}
	}
}

void init_debug_state(DebugState *dbg, char *bin_name, char **args) {
	memset(&dbg->sections, 0, sizeof(dbg->sections));
	load_elf_sections(&dbg->sections, bin_name);
	dbg->sections.args = args;

	get_dynamic_libraries(&dbg->sections);

	dbg->block_max = BLOCK_MAX;
	dbg->block_table = (Block *)calloc(sizeof(Block), dbg->block_max);
	dbg->block_len = 0;
	build_block_table(&dbg->sections, &dbg->block_table, &dbg->block_len, &dbg->block_max);

	dbg->line_tables_max = LINE_TABLES_MAX;
	dbg->line_tables = (CULineTable *)malloc(sizeof(CULineTable) * dbg->line_tables_max);
	dbg->line_tables_len = 0;
	build_line_tables(&dbg->sections, &dbg->line_tables, &dbg->line_tables_len, &dbg->line_tables_max);

	dbg->break_max = BREAKPOINTS_MAX;
	dbg->break_table = (Breakpoint *)calloc(sizeof(Breakpoint), dbg->break_max);
	dbg->break_len = 0;

	dbg->watch_max = WATCHPOINTS_MAX;
	dbg->watch_table = (Watchpoint *)calloc(sizeof(Watchpoint), dbg->watch_max);
	dbg->watch_len = 0;

	memset(dbg->hw_slots, 0, sizeof(dbg->hw_slots));
	dbg->hw_slots_max = HW_SLOTS_MAX;
	dbg->sw_watch_enabled = false;

	dbg->reset_idx = 0;
	dbg->should_reset = false;
}

void reset_checks(DebugState *dbg) {
	free(dbg->break_table);

	for (uint64_t i = 0; i < dbg->watch_len; i++) {
		free(dbg->watch_table[i].old_data);
		free(dbg->watch_table[i].new_data);
	}
	free(dbg->watch_table);

	dbg->break_max = BREAKPOINTS_MAX;
	dbg->break_table = (Breakpoint *)calloc(sizeof(Breakpoint), dbg->break_max);
	dbg->break_len = 0;

	dbg->watch_max = WATCHPOINTS_MAX;
	dbg->watch_table = (Watchpoint *)calloc(sizeof(Watchpoint), dbg->watch_max);
	dbg->watch_len = 0;

	memset(dbg->hw_slots, 0, sizeof(dbg->hw_slots));
	dbg->hw_slots_max = HW_SLOTS_MAX;
	dbg->sw_watch_enabled = false;

	dbg->reset_idx = 0;
	dbg->should_reset = false;
}

void free_debug_state(DebugState *dbg) {
	free(dbg->block_table);

	for (uint64_t i = 0; i < dbg->line_tables_len; i++) {
		free(dbg->line_tables[i].lines);
	}
	free(dbg->line_tables);
	free(dbg->break_table);

	for (uint64_t i = 0; i < dbg->watch_len; i++) {
		free(dbg->watch_table[i].old_data);
		free(dbg->watch_table[i].new_data);
	}
	free(dbg->watch_table);

	free(dbg->sections.bin_name);
	free(dbg->sections.file_buffer);

	memset(dbg, 0, sizeof(DebugState));
}

uint64_t find_next_line_addr_in_file(DebugState *dbg, char *break_file, uint32_t break_line) {
	uint64_t err = ~0;

	for (uint64_t i = 0; i < dbg->line_tables_len; i++) {
		CULineTable *line_table = &dbg->line_tables[i];
		int j;

		uint32_t break_file_idx = 0;
		for (j = 1; j < line_table->file_count; j++) {
			if (!(strcmp(line_table->filenames[j], break_file))) {
				break_file_idx = j;
				break;
			}
		}
		if (j == line_table->file_count) {
			return err;
		}

		for (int j = 0; j < line_table->line_count; j++) {
			LineMachine line = line_table->lines[j];

			if (line.line_num > break_line && break_file_idx == line.file_idx) {
				printf("next line from %u is %u, address 0x%lx\n", break_line, line.line_num, line.address);
				return line.address;
			}
		}
	}

	return err;
}

uint64_t find_line_addr_in_file(DebugState *dbg, char *break_file, uint32_t break_line) {
	uint64_t break_addr = ~0;

	for (uint64_t i = 0; i < dbg->line_tables_len; i++) {
		CULineTable *line_table = &dbg->line_tables[i];
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

	return break_addr;
}

typedef struct {
	uint64_t line;
	uint64_t address;
	char *file;
} FileLine;

int get_approx_line_for_addr(DebugState *dbg, uint64_t addr, FileLine *fl) {
	for (uint64_t i = 0; i < dbg->line_tables_len; i++) {
		CULineTable *line_table = &dbg->line_tables[i];

		for (int j = 0; j < line_table->line_count; j++) {
			LineMachine *line = &line_table->lines[j];

			if (line->address >= addr) {
				fl->line    = line->line_num;
				fl->address = line->address;
				fl->file    = line_table->filenames[line->file_idx];
				return 1;
			}
		}
	}

	return 0;
}

FuncFrame *find_function_frame(Block *block_table, uint64_t block_len, char *func_name, FuncFrame *ff) {
	for (uint64_t i = 0; i < block_len; i++) {
		Block *block = &block_table[i];
		if (block->type == DW_TAG_subprogram && block->name && strcmp(block->name, func_name) == 0) {
			ff->start = block->low_pc;
			ff->end = block->low_pc + block->high_pc;
			return ff;
		}
	}

	return NULL;
}

FuncFrame *find_function_frame_approx(DebugState *dbg, char *func_name, FuncFrame *ff) {
	if (find_function_frame(dbg->block_table, dbg->block_len, func_name, ff)) {
		ff->start += 4;

		FileLine fl = {0};
		if (!get_approx_line_for_addr(dbg, ff->start, &fl)) {
			panic("failed to get line for address!\n");
		}

		if (ff->end > fl.address) {
			ff->start = fl.address;
		}

		ff->end -= 1;
		return ff;
	}

	return NULL;
}

CurrentScopes *get_scopes(DebugState *dbg, uint64_t addr, CurrentScopes *sp) {
	uint64_t blk_idx = dbg->block_len - 1;
	Block *scope_block = NULL;
	for (; blk_idx > 0; blk_idx--) {
		Block *blk = &dbg->block_table[blk_idx];
		if ((addr >= blk->low_pc) && (addr <= (blk->low_pc + blk->high_pc))) {
			scope_block = blk;
			break;
		}
	}
	if (scope_block == NULL) {
		return NULL;
	}

	uint64_t scope_idx = blk_idx;
	uint64_t framed_scope_idx = 0;

	// Find nearest parent scope with frame_base_expr
	Block *framed_scope = NULL;
	if (scope_block->frame_base_expr) {
		framed_scope = scope_block;
		framed_scope_idx = scope_idx;
	} else {
		Block *tmp_scope_block = scope_block;
		uint64_t tmp_scope_block_idx = blk_idx;
		for (;;) {
			if (tmp_scope_block->parent_idx == tmp_scope_block_idx) {
				panic("parent == child, hotlooping\n");
			}

			if (tmp_scope_block->frame_base_expr) {
				framed_scope = tmp_scope_block;
				framed_scope_idx = tmp_scope_block_idx;
				break;
			}

			tmp_scope_block_idx = tmp_scope_block->parent_idx;
			tmp_scope_block = &dbg->block_table[tmp_scope_block_idx];
		}
	}

	sp->scope_idx = scope_idx;
	sp->framed_scope_idx = framed_scope_idx;

	return sp;
}

void eval_expr(struct user_regs_struct *regs, DWExprMachine *em, DWExpression in_ex, int depth) {
	for (uint64_t i = 0; i < in_ex.len; i++) {
		uint8_t op = in_ex.expr[i];

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
					panic("\nUnhandled op 0x%x, %s!\n", op, dwarf_expr_op_to_str(op));
				}
			}
		}
	}
}

// Intel Vol. 3B 17-5 - PG 3433-3434 -- covers debug register operation
void update_hw_breaks(DebugState *dbg, int pid, Block *framed_scope) {

	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	if (dbg->watch_len > HW_SLOTS_MAX) {
		panic("TODO Can't handle software watchpoints yet!\n");
	}

	memset(&dbg->hw_slots, 0, sizeof(dbg->hw_slots));
	int hw_slots_len = 0;
	int hw_slots_used = 0;
	int slot_off = 0;

	uint64_t dr7 = 0b00000000000000010000000100000000;
	for (uint64_t i = 0; i < dbg->watch_len; i++) {
		Watchpoint *wp = &dbg->watch_table[i];
		Block *var = &dbg->block_table[wp->var_idx];

		char width_bits = 0;
		int watchpoints_used = 5;
		if (wp->watch_width == 8) { width_bits = 0b10; watchpoints_used = 1; }
		else if (wp->watch_width == 4) { width_bits = 0b11; watchpoints_used = 1; }
		else if (wp->watch_width == 2) { width_bits = 0b01; watchpoints_used = 1; }
		else if (wp->watch_width == 1) { width_bits = 0b00; watchpoints_used = 1; }
		else if (wp->watch_width > 8) {
			width_bits = 0b10;

			int rem = !!(wp->watch_width % 8);
			watchpoints_used = (wp->watch_width / 8) + rem;
		} else {
			panic("unable to handle unaligned variables!\n");
		}

		if (hw_slots_used + watchpoints_used > HW_SLOTS_MAX) {
			panic("TODO Needs software watchpoint support!\n");
		}

		// Get variable address
		DWExprMachine em = {0};
		em.frame_holder = framed_scope;
		DWExpression ex = { .expr = var->loc_expr, .len = var->loc_expr_len };
		eval_expr(&regs, &em, ex, 0);

		uint64_t var_addr = em.val_stack[0];

		if (wp->member_idx) {
			var_addr += wp->member_offset;
		}

		int is_8b_aligned = (var_addr & 0x7) == 0;
		int is_4b_aligned = (var_addr & 0x3) == 0;
		int is_2b_aligned = (var_addr & 0x1) == 0;

		//printf("8 %d, 4 %d, 2 %d\n", is_8b_aligned, is_4b_aligned, is_2b_aligned);
		if (!(is_8b_aligned || is_4b_aligned || is_2b_aligned || wp->watch_width == 1)) {
			panic("Unable to handle unaligned watchpoints!\n");
		}

		HWBreak *br = &dbg->hw_slots[hw_slots_len];
		br->type = HWWatchpoint;
		br->idx = i;
		hw_slots_len++;
		hw_slots_used += watchpoints_used;

		memset(wp->old_data, 0, wp->watch_width);

		uint64_t rem_width = wp->watch_width;
		uint64_t leftovers;
		for (int j = 0; j < watchpoints_used; j++) {
			if (rem_width > 8) {
				leftovers = 8;
				rem_width -= 8;
			} else {
				leftovers = rem_width;
				rem_width = 0;
			}

			uint64_t cur_val = ptrace(PTRACE_PEEKDATA, pid, (void *)(var_addr + (j * 8)), NULL);
			memcpy(wp->old_data + (j * 8), &cur_val, leftovers);
			
			int width_off = 18 + (4 * slot_off);
			int watchtype_off = 16 + (4 * slot_off);
			int register_enable_off = 2 * slot_off;
			int reg_idx = slot_off;

			printf("[0x%llx] adding %s with width %lu and offset %lx to watchlist\n", regs.rip, var->name, wp->watch_width, wp->member_offset);
			printf("%u, %u, %u, %u, %u\n", width_off, watchtype_off, register_enable_off, reg_idx, width_bits);

			// set: width | watch type (write only) | # register enable
			dr7 |= (width_bits << width_off) | (0b01 << watchtype_off) | (0b1 << register_enable_off);
			ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[reg_idx]), (void *)(var_addr + (j * 8)));

			slot_off++;
		}
	}

	printf("Setting dr7 to 0x%lx -- %lu watchpoints\n", dr7, dbg->watch_len);
	if (ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[7]), (void *)dr7) == -1) {
		panic("Failed to set dr7 correctly!\n");
	}
	if (ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[6]), NULL)) {
		panic("failed to zero dr6!\n");
	}
}

void inject_breakpoint_at_addr(int pid, Breakpoint *br, uint64_t addr) {
	uint64_t orig_data = (uint64_t)ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);

	// Replace first byte of code at address with int 3
	uint64_t data_with_trap = (orig_data & (~0xFF)) | 0xCC;

	ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)data_with_trap);

	br->address = addr;
	br->orig_data = orig_data;
}

void add_breakpoint(int pid, Breakpoint *br, uint64_t addr, bool permanent) {
	if (br->ref_count > 0) {
		printf("Doing a ref skip!\n");
		goto ref_end;
	}

	inject_breakpoint_at_addr(pid, br, addr);

ref_end:
	if (permanent) {
		br->ref_count += 1;
	}
}

void reset_breakpoint(DebugState *dbg, int pid) {
	ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

	int status;
	waitpid(pid, &status, 0);
	if (!WIFSTOPPED(status)) {
		panic("Failure to break on watchpoint\n");
	}

	Breakpoint *br = &dbg->break_table[dbg->reset_idx];

	inject_breakpoint_at_addr(pid, br, br->address);

	dbg->reset_idx = 0;
	dbg->should_reset = false;
}

void cleanup_watchpoints(DebugState *dbg, int pid, uint64_t break_addr) {
	if (!dbg->watch_len) {
		return;
	}

	uint64_t break_idx = (uint64_t)~0;
	for (uint64_t i = 0; i < dbg->break_len; i++) {
		Breakpoint *br = &dbg->break_table[i];
		if (br->address == break_addr) {
			break_idx = i;
			break;
		}
	}
	if (break_idx == (uint64_t)~0) {
		return;
	}

	// Get all watchpoints associated with breakpoint, clean up
	Breakpoint *br = &dbg->break_table[break_idx];
	for (uint64_t j = dbg->watch_len - 1; j > 0; j--) {
		Watchpoint *wp = &dbg->watch_table[j];
		if (wp->break_idx == break_idx) {
			Watchpoint *end = &dbg->watch_table[dbg->watch_len];
			Watchpoint *old = &dbg->watch_table[j];

			free(old->old_data);
			free(old->new_data);
			memcpy(old, end, sizeof(Watchpoint));
			memset(end, 0, sizeof(Watchpoint));
			dbg->watch_len--;

			br->ref_count -= 1;
		}
	}

	CurrentScopes scopes = {0};
	if (!get_scopes(dbg, break_addr, &scopes)) {
		printf("Failed to find scope!\n");
		return;
	}

	update_hw_breaks(dbg, pid, &dbg->block_table[scopes.framed_scope_idx]);
}


VarInfo get_var_for_name(DebugState *dbg, CurrentScopes *scopes, char *var_name) {
	uint64_t var_name_len = strlen(var_name);
	char *_varstr = (char *)malloc(var_name_len + 1);
	strcpy(_varstr, var_name);

	char *members[MEMBERS_MAX] = {0};
	uint64_t members_len = 0;

	VarInfo info = {0};
	info.var_idx = (uint64_t)~0;

	char *ptr = _varstr;
	char *head = ptr;
	while (*ptr) {
		if (*ptr == '.') {
			*ptr = 0;

			if (members_len + 1 > MEMBERS_MAX) {
				panic("No more room for more members!\n");
			}

			members[members_len++] = head;
			head = ptr + 1;
		}

		ptr++;
	}
	if (head != ptr) {
		if (members_len + 1 > MEMBERS_MAX) {
			panic("No more room for more members!\n");
		}
		members[members_len++] = head;
	}
	if (!members_len) {
		goto find_var_end;
	}

	char *_var_name = members[0];
	uint64_t blk_idx = scopes->scope_idx;

	// Find variable in scope by descending tree from scope_block (can pass into other scopes)
	Block *var_block = NULL;
	for (; blk_idx < dbg->block_len; blk_idx++) {
		Block *blk = &dbg->block_table[blk_idx];
		if (blk->name && strcmp(blk->name, _var_name) == 0 && (blk->type == DW_TAG_variable || blk->type == DW_TAG_formal_parameter)) {
			var_block = blk;
			break;
		}
	}

	// Try using the framed scope idx instead if we couldn't find it in the lexical scope
	if (var_block == NULL) {
		blk_idx = scopes->framed_scope_idx;
		for (; blk_idx < dbg->block_len; blk_idx++) {
			Block *blk = &dbg->block_table[blk_idx];
			if (blk->name && strcmp(blk->name, _var_name) == 0 && blk->type == DW_TAG_variable) {
				var_block = blk;
				break;
			}
		}
		if (var_block == NULL) {
			printf("Unable to find variable %s in scope!\n", _var_name);
			goto find_var_end;
		}
	}

	uint64_t var_idx = blk_idx;
		
	// Walk parent_idx to confirm that variable obtained in last pass belongs to current scope
	Block *tmp_var_block = var_block;
	uint64_t tmp_var_block_idx = var_idx;
	for (;;) {
		if (scopes->scope_idx == tmp_var_block_idx || scopes->framed_scope_idx == tmp_var_block_idx) {
			break;
		}

		if (!tmp_var_block->parent_idx) {
			panic("hit scope max, %s\n", tmp_var_block->name);
		}

		if (tmp_var_block->parent_idx == tmp_var_block_idx) {
			panic("Invalid parent, hotlooping\n");
		}

		tmp_var_block_idx = tmp_var_block->parent_idx;
		if (!tmp_var_block_idx) {
			panic("Unable to lookup parent of entry!\n");
		}

		tmp_var_block = &dbg->block_table[tmp_var_block_idx];
	}

	info.var_idx = var_idx;

	if (members_len == 1) {
		// Resolve type for variable to get width
		Block *tmp_block = var_block;
		for (;;) {
			if (!tmp_block->type_idx) {
				break;
			}

			tmp_block = &dbg->block_table[tmp_block->type_idx];
		}

		info.width = tmp_block->type_width;
		goto find_var_end;
	}
		
	
/*
 * Resolve struct members
 * find each member, confirm they live as part of the variables struct
 * get member offset, add to running offset tally
 *
 */

	Block *struct_block = var_block;
	uint64_t struct_idx = 0;
	for (;;) {
		if (!struct_block->type_idx) {
			break;
		}

		struct_idx = struct_block->type_idx;
		struct_block = &dbg->block_table[struct_block->type_idx];
	}

	uint64_t var_offset = 0;
	uint64_t var_width = 0;
	uint64_t member_idx = 0;
	for (uint64_t i = 1; i < members_len; i++) {
		char *sub_name = members[i];

		for (uint64_t j = struct_idx + 1; j < dbg->block_len; j++) {
			Block *member_block = &dbg->block_table[j];	
			if (!strcmp(member_block->name, sub_name)) {
				member_idx = j;
				break;
			}

			if (member_block->parent_idx != struct_idx) {
				printf("Couldn't find member %s for struct!\n", sub_name);
				goto find_var_end;
			}
		}
		if (!member_idx) {
			printf("Couldn't find member %s for struct!\n", sub_name);
			goto find_var_end;
		}

		Block *member_block = &dbg->block_table[member_idx];

		Block *substruct_block = member_block;
		uint64_t substruct_idx = 0;
		for (;;) {
			if (!substruct_block->type_idx) {
				break;
			}

			substruct_idx = substruct_block->type_idx;
			substruct_block = &dbg->block_table[substruct_block->type_idx];
		}

		struct_block = substruct_block;
		struct_idx = substruct_idx;
		var_width = substruct_block->type_width;

		var_offset += member_block->member_offset;
	}

	info.member_idx = member_idx;
	info.member_offset = var_offset;
	info.width = var_width;

find_var_end:
	free(_varstr);
	return info;
}

void add_watchpoint(DebugState *dbg, int pid, char *var_name) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	CurrentScopes scopes = {0};
	if (!get_scopes(dbg, regs.rip, &scopes)) {
		printf("Failed to find scope!\n");
		return;
	}

	VarInfo info = get_var_for_name(dbg, &scopes, var_name);
	if (info.var_idx == (uint64_t)~0) {
		return;
	}

	Block *framed_scope = &dbg->block_table[scopes.framed_scope_idx];
	Block *scope_block = &dbg->block_table[scopes.scope_idx];

	Watchpoint *var_watch = NULL;
	uint64_t watch_idx = 0;
	for (uint64_t i = 0; i < dbg->watch_len; i++) {
		Watchpoint *wp = &dbg->watch_table[i];
		if (wp->var_idx == info.var_idx) {
			var_watch = wp;
			watch_idx = i;
			break;
		}
	}
	if (var_watch == NULL) {
		// If this is a function, add buffer zone for the pre/postambles
		uint64_t end;
		if (scopes.framed_scope_idx == scopes.scope_idx) {
			FuncFrame ff = {0};
			if (!find_function_frame_approx(dbg, framed_scope->name, &ff)) {
				panic("Failed to find function frame for function\n");
			}

			end = ff.end;
		} else {
			end = scope_block->low_pc + scope_block->high_pc;
		}

		Watchpoint *wp = &dbg->watch_table[dbg->watch_len];
		wp->end = end;
		wp->var_idx = info.var_idx;
		wp->member_idx = info.member_idx;
		wp->member_offset = info.member_offset;
		watch_idx = dbg->watch_len;

		// establish a breakpoint so we can clean up the watchpoint when it drops out of scope
		wp->break_idx = (uint64_t)~0;
		for (uint64_t i = 0; i < dbg->break_len; i++) {
			Breakpoint *br = &dbg->break_table[i];
			if (br->address == wp->end) {
				wp->break_idx = i;
				br->ref_count += 1;
				break;
			}
		}
		if (wp->break_idx == (uint64_t)~0) {
			if (dbg->break_len + 1 > dbg->break_max) {
				panic("TODO 3 This should probably be dynamic!\n");
			}

			Breakpoint *br = &dbg->break_table[dbg->break_len];
			printf("Breakpoint added @ 0x%lx\n", wp->end);
			add_breakpoint(pid, br, wp->end, true);
			dbg->break_len++;
		}
		

		wp->watch_width = info.width;
		wp->old_data = (uint8_t *)calloc(wp->watch_width, sizeof(uint8_t));
		wp->new_data = (uint8_t *)calloc(wp->watch_width, sizeof(uint8_t));

		dbg->watch_len++;
		var_watch = wp;
	}

	update_hw_breaks(dbg, pid, framed_scope);
}

void continue_to_next(DebugState *dbg, int pid, bool single_step) {
	struct user_regs_struct regs;

	if (dbg->should_reset) {
		printf("Resetting breakpoint?\n");
		reset_breakpoint(dbg, pid);
	}

	if (single_step) {
		ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
	} else {
		ptrace(PTRACE_CONT, pid, NULL, NULL);
	}

	int status;
	waitpid(pid, &status, 0);
	if (!WIFSTOPPED(status)) {
		int ret_val = WEXITSTATUS(status);
		printf("Program died with return code %d, bye!\n", ret_val);
		dbg->needs_restart = true;
		return;
	}

	uint64_t dr6 = ptrace(PTRACE_PEEKUSER, pid, (void *)offsetof(struct user, u_debugreg[6]), NULL);

	uint32_t triggerbits = dr6 & 0b1111;
/*
	int dr7_set        = (dr6 >> 12) & 1;
	int single_stepped = (dr6 >> 14) & 1;
*/


	if (ptrace(PTRACE_POKEUSER, pid, (void *)offsetof(struct user, u_debugreg[6]), NULL)) {
		panic("failed to set up dr6!\n");
	}

	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	FileLine fl = {0};
	if (!get_approx_line_for_addr(dbg, regs.rip - 1, &fl)) {
		printf("Stopped @ 0x%llx\n", regs.rip);
	} else {
		printf("Stopped @ 0x%llx | line %lu in file %s\n", regs.rip, fl.line, fl.file);
	}

	if (triggerbits) {
		CurrentScopes scopes = {0};
		if (!get_scopes(dbg, regs.rip, &scopes)) {
			return;
		}

		for (uint64_t i = 0; i < dbg->hw_slots_max; i++) {
			HWBreak *br = &dbg->hw_slots[i];
			if (br->type != HWWatchpoint) {
				triggerbits = triggerbits >> 1;
				continue;
			}

			Watchpoint *wp = &dbg->watch_table[br->idx];
			Block *var = &dbg->block_table[wp->var_idx];

			int watchpoints_used = 5;
			if (wp->watch_width <= 8) {
				watchpoints_used = 1; 
			} else if (wp->watch_width > 8) {
				int rem = !!(wp->watch_width % 8);
				watchpoints_used = (wp->watch_width / 8) + rem;
			}
			assert(watchpoints_used > 4, "unable to handle large watchpoints\n");

			uint8_t bitmasks[HW_SLOTS_MAX] = { 0b0001, 0b0011, 0b0111, 0b1111 };
			printf("triggerbits: %u; bits: %u; watchpoints: %u\n", triggerbits, triggerbits & bitmasks[watchpoints_used - 1], watchpoints_used);
			if (!(triggerbits & bitmasks[watchpoints_used - 1])) {
				printf("Skipping thing here!\n");
				triggerbits = triggerbits >> watchpoints_used;
				continue;
			}
			triggerbits = triggerbits >> watchpoints_used;

			// Find variable address
			DWExprMachine em = {0};
			em.frame_holder = &dbg->block_table[scopes.framed_scope_idx];
			DWExpression ex = { .expr = var->loc_expr, .len = var->loc_expr_len };
			eval_expr(&regs, &em, ex, 0);
			uint64_t var_addr = em.val_stack[0];

			if (wp->member_idx) {
				var_addr += wp->member_offset;
			}

			int is_8b_aligned = (var_addr & 0x7) == 0;
			int is_4b_aligned = (var_addr & 0x3) == 0;
			int is_2b_aligned = (var_addr & 0x1) == 0;

			// printf("8 %d, 4 %d, 2 %d\n", is_8b_aligned, is_4b_aligned, is_2b_aligned);
			if (!(is_8b_aligned || is_4b_aligned || is_2b_aligned || wp->watch_width == 1)) {
				panic("Unable to handle unaligned watchpoints!\n");
			}

			memset(wp->new_data, 0, wp->watch_width);
			uint64_t rem_width = wp->watch_width;
			uint64_t leftovers;
			for (int j = 0; j < watchpoints_used; j++) {
				if (rem_width > 8) {
					leftovers = 8;
					rem_width -= 8;
				} else {
					leftovers = rem_width;
					rem_width = 0;
				}

				uint64_t cur_val = ptrace(PTRACE_PEEKDATA, pid, (void *)(var_addr + (j * 8)), NULL);
				memcpy(wp->new_data + (j * 8), &cur_val, leftovers);
			}

			if (wp->watch_width <= 8) {
				uint64_t old_data = 0;
				uint64_t new_data = 0;
				memcpy(&old_data, wp->old_data, wp->watch_width);
				memcpy(&new_data, wp->new_data, wp->watch_width);
				printf("[0x%llx] Variable %s changed from %lu to %lu | %lu\n", regs.rip, var->name, old_data, new_data, wp->watch_width);
			} else {
				printf("[0x%llx] Variable %s changed from %u to %u | %lu\n", regs.rip, var->name, wp->old_data[0], wp->new_data[0], wp->watch_width);
			}
			memcpy(wp->old_data, wp->new_data, wp->watch_width);
		}
	}

	uint64_t prev_address = regs.rip - 1;
	uint64_t prev_inst = ptrace(PTRACE_PEEKDATA, pid, (void *)prev_address, NULL);

	// check if we just stepped over a trap that needs to be patched
	if ((prev_inst & 0xFF) != 0xCC) {
		return;
	}

	cleanup_watchpoints(dbg, pid, prev_address);

	// There should only ever be 1 breakpoint per address
	// (prevents replacing good orig_data with a trap unintentionally)
	Breakpoint *break_check = NULL;
	uint64_t i = 0;
	for (; i < dbg->break_len; i++) {
		Breakpoint *br = &dbg->break_table[i];

		if (prev_address == br->address) {
			break_check = br;
			break;
		}
	}
	if (!break_check) {
		panic("Couldn't find breakpoint for 0x%lx?\n", prev_address);
	}

	ptrace(PTRACE_POKEDATA, pid, (void *)break_check->address, (void *)break_check->orig_data);
	regs.rip -= 1;
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);

	if (break_check->ref_count > 0) {
		dbg->reset_idx = i;
		dbg->should_reset = true;
	}

	// Garbage collect breakpoints if they exist. This *shouldn't* cause watch/break indexing issues, 
	// because the watchpoints referring to the now bad breakpoint idx *should* already be gone
	if (!dbg->break_len) {
		return;
	}

	for (uint64_t i = dbg->break_len - 1; i > 0; i--) {
		Breakpoint *br = &dbg->break_table[i];
		if (br->ref_count == 0) {
			Breakpoint *end = &dbg->break_table[dbg->break_len];
			Breakpoint *old = &dbg->break_table[i];

			memcpy(old, end, sizeof(Breakpoint));
			memset(end, 0, sizeof(Breakpoint));
			dbg->break_len--;
		}
	}

	for (uint64_t i = 0; i < dbg->break_len; i++) {
		Breakpoint *br = &dbg->break_table[i];
		if (br->address == prev_address && br->ref_count > 0) {
			dbg->reset_idx = i;
			break;
		}
	}
}

void gather_registers(int pid, dol_t *p) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	p->offset += sprintf((char *)p->data + p->offset, "RIP: 0x%llx\n", regs.rip);
	p->offset += sprintf((char *)p->data + p->offset, "RAX: 0x%llx\n", regs.rax);
	p->offset += sprintf((char *)p->data + p->offset, "RBX: 0x%llx\n", regs.rbx);
	p->offset += sprintf((char *)p->data + p->offset, "RCX: 0x%llx\n", regs.rcx);
	p->offset += sprintf((char *)p->data + p->offset, "RDX: 0x%llx\n", regs.rdx);
	p->offset += sprintf((char *)p->data + p->offset, "RDI: 0x%llx\n", regs.rdi);
	p->offset += sprintf((char *)p->data + p->offset, "RSI: 0x%llx\n", regs.rsi);
	p->offset += sprintf((char *)p->data + p->offset, "RSP: 0x%llx\n", regs.rsp);
	p->offset += sprintf((char *)p->data + p->offset, "RBP: 0x%llx\n", regs.rbp);
	p->offset += sprintf((char *)p->data + p->offset, "R8: 0x%llx\n",  regs.r8);
	p->offset += sprintf((char *)p->data + p->offset, "R9: 0x%llx\n",  regs.r9);
	p->offset += sprintf((char *)p->data + p->offset, "R10: 0x%llx\n", regs.r10);
	p->offset += sprintf((char *)p->data + p->offset, "R11: 0x%llx\n", regs.r11);
	p->offset += sprintf((char *)p->data + p->offset, "R12: 0x%llx\n", regs.r12);
	p->offset += sprintf((char *)p->data + p->offset, "R13: 0x%llx\n", regs.r13);
	p->offset += sprintf((char *)p->data + p->offset, "R14: 0x%llx\n", regs.r14);
	p->offset += sprintf((char *)p->data + p->offset, "R15: 0x%llx\n", regs.r15);
}

void goto_next_flowline(DebugState *dbg, int pid) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	FileLine fl = {0};
	if (!get_approx_line_for_addr(dbg, regs.rip, &fl)) {
		panic("failed to get line for rip!\n");
	}

	uint64_t break_addr = find_next_line_addr_in_file(dbg, fl.file, fl.line);
	if (break_addr == (uint64_t)~0) {
		printf("Unable to find line after %lu\n", fl.line);
		return;
	}

	Breakpoint *br = &dbg->break_table[dbg->break_len++];
	add_breakpoint(pid, br, break_addr, false);
	printf("Set breakpoint @ 0x%lx\n", break_addr);
	continue_to_next(dbg, pid, false);
}

void goto_next_line(DebugState *dbg, int pid) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);

	FileLine fl = {0};
	if (!get_approx_line_for_addr(dbg, regs.rip, &fl)) {
		panic("failed to get line for rip!\n");
	}

	uint64_t break_addr = find_next_line_addr_in_file(dbg, fl.file, fl.line);
	if (break_addr == (uint64_t)~0) {
		printf("Unable to find line after %lu\n", fl.line);
		return;
	}

	Breakpoint *br = &dbg->break_table[dbg->break_len++];
	add_breakpoint(pid, br, break_addr, false);
	printf("Set breakpoint @ 0x%lx\n", break_addr);
	continue_to_next(dbg, pid, false);
}

int start_debugger(char *bin_name, char **args) {
	int pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);

		// Turn off stack address randomization for more consistent debugging
		personality(ADDR_NO_RANDOMIZE);
		execvp(bin_name, args);

		panic("Failed to run program %s\n", bin_name);
	} else if (pid < 0) {
		panic("Failed to fork?\n");
	}

	int status;
	waitpid(pid, &status, 0);
	return pid;
}

int process_command(DebugState *dbg, int *cpid, char *line, uint64_t line_size, dol_t *outbuf) {
	struct user_regs_struct regs;

	int pid = *cpid;

	if (!strcmp(line, "c")) {
		continue_to_next(dbg, pid, false);
	} else if (line_size > 3 && line[0] == 'r' && line[1] == ' ') {
/*
		free_debug_state(dbg);

		int ret = kill(pid, SIGKILL);
		if (ret == -1) {
			panic("Process too attached to children\n");
		}

		char path[PATH_MAX + 1] = {0};
		uint64_t path_size = line_size - 2;
		memcpy(path, line + 2, path_size);

		char *args_arr[PATH_MAX + 1] = {0};
		int args_len = 0;
		char *last_arg = path;
		uint64_t i = 0;
		for (;i < path_size; i++) {
			if (path[i] == '\n' || path[i] == '\0') {
				break;
			}

			if (path[i] == ' ') {
				args_arr[args_len++] = last_arg;
				path[i] = '\0';
				last_arg = path + 1;
			}
		}
		if (i == path_size) {
			args_arr[args_len++] = last_arg;
			path[i + 1] = '\0';
		}

		init_debug_state(dbg, args_arr[0]);
		*cpid = start_debugger(args_arr[0], args_arr + 1);
*/
	} else if (!strcmp(line, "r")) {
		int ret = kill(pid, SIGKILL);
		if (ret == -1) {
			panic("Process too attached to children\n");
		}

		reset_checks(dbg);

		*cpid = start_debugger(dbg->sections.bin_name, dbg->sections.args);
	} else if (line_size > 3 && line[0] == 'r' && line[1] == ' ') {
		free_debug_state(dbg);

		int ret = kill(pid, SIGKILL);
		if (ret == -1) {
			panic("Process too attached to children\n");
		}

		char path[PATH_MAX + 1] = {0};
		uint64_t path_size = line_size - 2;
		memcpy(path, line + 2, path_size);

		char *args_arr[PATH_MAX + 1] = {0};
		int args_len = 0;
		char *last_arg = path;
		uint64_t i = 0;
		for (;i < path_size; i++) {
			if (path[i] == '\n' || path[i] == '\0') {
				break;
			}

			if (path[i] == ' ') {
				args_arr[args_len++] = last_arg;
				path[i] = '\0';
				last_arg = path + 1;
			}
		}
		if (i == path_size) {
			args_arr[args_len++] = last_arg;
			path[i + 1] = '\0';
		}

		*cpid = start_debugger(args_arr[0], args_arr + 1);
	} else if (!strcmp(line, "fs")) {
		uint64_t cu_count = 0;
		for (uint64_t i = 0; i < dbg->block_len; i++) {
			Block *b = &dbg->block_table[i];	
			if (b->type == DW_TAG_compile_unit) {
				printf("looking for files for %s\n", b->name);

				CULineTable *line_table = &dbg->line_tables[cu_count++];
				char *dir  = NULL;
				char *name = NULL;

				char tmp_path[PATH_MAX + 1] = {0};
				for (int j = 0; j < line_table->file_count; j++) {
					uint8_t dir_idx = line_table->dir_idx[j];
					char *dirname = line_table->dirs[dir_idx];
					if (!line_table->filenames[j]) {
						continue;
					}

					printf("TESTING %s | %s == %s | %s\n", dirname, line_table->filenames[j], b->comp_dir, b->name);
					sprintf(tmp_path, "%s/%s", dirname, line_table->filenames[j]);	
					if (!strcmp(line_table->filenames[j], b->name)) {
						printf("FOUND %s | %s == %s\n", dirname, line_table->filenames[j], b->name);
						dir = b->comp_dir;
						name = b->name;
						break;
					}
				}

				outbuf->offset += sprintf((char *)outbuf->data + outbuf->offset, "%s %s %s\n", "", dir, name);
				if (outbuf->offset > outbuf->length) {
					panic("too many file paths!\n");
				}
			}
		}
	} else if (!strcmp(line, "pb")) {
		for (uint64_t i = 0; i < dbg->break_len; i++) {
			Breakpoint *bp = &dbg->break_table[i];

			FileLine fl = {0};
			if (!get_approx_line_for_addr(dbg, bp->address, &fl)) {
				outbuf->offset += sprintf((char *)outbuf->data + outbuf->offset, "0x%lx\n", bp->address);
			} else {
				outbuf->offset += sprintf((char *)outbuf->data + outbuf->offset, "0x%lx %lu %s\n", bp->address, fl.line, fl.file);
			}

			if (outbuf->offset > outbuf->length) {
				panic("too many breakpoints!\n");
			}
		}
	} else if (!strcmp(line, "pc")) {
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		FileLine fl = {0};
		if (!get_approx_line_for_addr(dbg, regs.rip, &fl)) {
			outbuf->offset += sprintf((char *)outbuf->data + outbuf->offset, "0x%llx\n", regs.rip);
		} else {
			outbuf->offset += sprintf((char *)outbuf->data + outbuf->offset, "0x%llx %lu %s\n", regs.rip, fl.line, fl.file);
		}
	} else if (!strcmp(line, "pw")) {
		for (uint64_t i = 0; i < dbg->watch_len; i++) {
			Watchpoint *wp = &dbg->watch_table[i];
			Block *var = &dbg->block_table[wp->var_idx];

			if (wp->watch_width <= 8) {
				uint64_t data = 0;
				memcpy(&data, wp->new_data, wp->watch_width);
				outbuf->offset += sprintf((char *)outbuf->data + outbuf->offset, "%lu %lu %s\n", i, data, var->name);
			} else {
				outbuf->offset += sprintf((char *)outbuf->data + outbuf->offset, "%lu 0x%lx %s\n", i, (uint64_t)wp->new_data, var->name);
			}

			if (outbuf->offset > outbuf->length) {
				panic("too many watchpoints!\n");
			}
		}
	} else if (line_size > 3 && line[0] == 'w' && line[1] == ' ') {
		char *watch_name = line + 2;
		add_watchpoint(dbg, pid, watch_name);
	} else if (line_size > 3 && line[0] == 'b' && line[1] == ' ') {
		char *break_str = line + 2;

		char *break_end;
		uint64_t break_addr = strtol(break_str, &break_end, 0);
		if (break_str == break_end) {
			printf("Invalid breakpoint address: %s\n", break_str);
			return 0;
		}

		Breakpoint *br = &dbg->break_table[dbg->break_len++];
		add_breakpoint(pid, br, break_addr, true);
		printf("Set breakpoint @ 0x%lx\n", break_addr);
	} else if (line_size > 4 && line[0] == 'b' && line[1] == 'l' && line[2] == ' ') {
		char *break_str = line + 3;

		char *break_end;
		uint64_t break_line_num = strtol(break_str, &break_end, 0);
		if (break_str == break_end) {
			printf("Invalid line break: %s\n", break_str);
			return 0;
		}

		uint64_t rem_size = strlen(break_end);
		printf("%s | %lu\n", break_end, rem_size);
		if (break_end[0] != ' ') {
			printf("command requires a file name\n");
			return 0;
		}

		char *file_name = break_end + 1;

		uint64_t break_addr = find_line_addr_in_file(dbg, file_name, break_line_num);
		if (break_addr == (uint64_t)~0) {
			printf("Unable to find line %lu\n", break_line_num);
			return 0;
		}

		Breakpoint *br = &dbg->break_table[dbg->break_len++];
		add_breakpoint(pid, br, break_addr, true);
		printf("Set breakpoint @ 0x%lx\n", break_addr);
	} else if (!strcmp(line, "s")) {
		goto_next_line(dbg, pid);
	} else if (!strcmp(line, "si")) {
		goto_next_flowline(dbg, pid);
	} else if (!strcmp(line, "sa")) {
		continue_to_next(dbg, pid, true);
	} else if (!strcmp(line, "p")) {
		gather_registers(pid, outbuf);
	} else if (line_size > 3 && line[0] == 'p' && line[1] == ' ') {
		char *var_name = line + 2;

		struct user_regs_struct regs;
		ptrace(PTRACE_GETREGS, pid, NULL, &regs);

		CurrentScopes scopes = {0};
		if (!get_scopes(dbg, regs.rip, &scopes)) {
			printf("Failed to find scope!\n");
			return 0;
		}

		VarInfo info = get_var_for_name(dbg, &scopes, var_name);
		if (info.var_idx == (uint64_t)~0) {
			printf("Failed to find variable %s\n", var_name);
			return 0;
		}

		Block *var = &dbg->block_table[info.var_idx];

		// Get variable address
		DWExprMachine em = {0};
		em.frame_holder = &dbg->block_table[scopes.framed_scope_idx];
		DWExpression ex = { .expr = var->loc_expr, .len = var->loc_expr_len };
		eval_expr(&regs, &em, ex, 0);

		uint64_t var_addr = em.val_stack[0];

		if (info.member_idx) {
			var_addr += info.member_offset;
		}

		uint64_t cur_val = ptrace(PTRACE_PEEKDATA, pid, (void *)var_addr, NULL);
		if (info.width <= 8) {
			uint64_t data = 0;
			memcpy(&data, &cur_val, info.width);
			printf("%s == %lu, width: %lu\n", var_name, cur_val, info.width);
		} else {
			printf("%s chunk: %lx\n", var_name, cur_val);
		}
	} else if (!strcmp(line, "q")) {
		happy_death("program closed!\n");
	} else {
		printf("Command %s not recognized\n", line);
		return 0;
	}

	return 1;
}

#ifdef LOCAL
int main(int argc, char **argv) {
	if (argc < 2) {
		panic("Please provide the debugger a program to debug!\n");
	}
	
	//print_block_table(dbg.block_table, dbg.block_len);
	//print_line_table(dbg.line_tables, dbg.line_tables_len);

	DebugState dbg = {0};
	init_debug_state(&dbg, argv[1], argv + 1);
	int pid = start_debugger(argv[1], argv + 1);

	char *cmds[] = { "fs" };
	uint64_t num_cmds = sizeof(cmds) / sizeof(*cmds);

	for (uint64_t i = 0; i < num_cmds; i++) {
		uint8_t outbuf[OUTBUF_MAX] = {0};
		dol_t out = { .data = outbuf, .offset = 0, .length = OUTBUF_MAX };
		uint8_t packetbuf[OUTBUF_MAX + 5] = {0};
		dol_t packet = { .data = packetbuf, .offset = 0, .length = OUTBUF_MAX + 5 };

		uint64_t cmd_size = strlen(cmds[i]);
		printf("<%lu> RECV: [%.*s]\n", i, (int)cmd_size, cmds[i]);

		int ret = process_command(&dbg, &pid, cmds[i], cmd_size, &out);

		if (dbg.needs_restart) {
			reset_checks(&dbg);
			pid = start_debugger(dbg.sections.bin_name, dbg.sections.args);
			dbg.needs_restart = false;
		}

		if (ret) {
			packet.offset = sprintf((char *)packet.data, "ok %lu %.*s", out.offset, (int)out.offset, out.data);
		} else {
			packet.offset = sprintf((char *)packet.data, "no %lu %.*s", out.offset, (int)out.offset, out.data);
		}

		printf("<%lu> SEND: [%.*s]\n", i, (int)packet.offset, packet.data);
	}
}
#else
int main(int argc, char **argv) {
	if (argc < 2) {
		panic("Please provide the debugger a program to debug!\n");
	}

	DebugState dbg = {0};
	init_debug_state(&dbg, argv[1], argv + 1);
	int pid = start_debugger(argv[1], argv + 1);

	//print_block_table(dbg.block_table, dbg.block_len);
	//print_line_table(dbg.line_tables, dbg.line_tables_len);

	struct sockaddr_in serv_addr = {0};
	uint16_t port = 5000;
	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(port);

	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
		panic("failed to set reuse addr?\n");
	}

	bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	printf("Debugger listening on port %d\n", port);
	listen(listen_fd, 1);

	int conn_fd = accept(listen_fd, (struct sockaddr *)NULL, NULL);


	uint8_t outbuf[OUTBUF_MAX] = {0};
	dol_t out = { .data = outbuf, .offset = 0, .length = OUTBUF_MAX };
	uint8_t packetbuf[OUTBUF_MAX + 5] = {0};
	dol_t packet = { .data = packetbuf, .offset = 0, .length = OUTBUF_MAX + 5 };

	char line_buffer[LINE_BUFFER_MAX + 1];
	uint64_t used_bytes = 0;
	for (;;) {
		uint64_t rem_bytes = LINE_BUFFER_MAX - used_bytes;
		if (!rem_bytes) {
			panic("input buffer full!\n");
		}

		ssize_t ret_size = recv(conn_fd, line_buffer + used_bytes, rem_bytes, 0);
		if (!ret_size) {
			happy_death("GUI server closed!\n");
		} else if (ret_size < 0) {
			panic("recv failed!\n");
		}

		uint64_t line_start = used_bytes;
		uint64_t new_start = line_start;
		used_bytes += ret_size;

		for (uint64_t i = line_start; i < used_bytes; i++) {
			if (line_buffer[i] == '\n') {
				line_buffer[i] = 0;
//				printf("RECV %lu [%.*s]\n", i - new_start, (int)(i - new_start), line_buffer + new_start);

				int ret = process_command(&dbg, &pid, line_buffer + new_start, i - new_start, &out);

				if (dbg.needs_restart) {
					reset_checks(&dbg);
					pid = start_debugger(dbg.sections.bin_name, dbg.sections.args);
					dbg.needs_restart = false;
				}

				new_start = i + 1;

				if (out.offset > out.length) {
					panic("outbound buffer too full!\n");
				}

				if (ret) {
					packet.offset = sprintf((char *)packet.data, "ok %lu %.*s", out.offset, (int)out.offset, out.data);
				} else {
					packet.offset = sprintf((char *)packet.data, "no %lu %.*s", out.offset, (int)out.offset, out.data);
				}

//				printf("SEND %lu [%s]\n", packet.offset, packet.data);

				ssize_t ret_size = send(conn_fd, packet.data, packet.offset, 0);
				if (!ret_size) {
					happy_death("GUI server closed!\n");
				} else if (ret_size < 0) {
					panic("recv failed!\n");
				}

				memset(out.data, 0, ret_size);
				memset(packet.data, 0, packet.offset);
				out.offset = 0;
				packet.offset = 0;
			}
		}

		memmove(line_buffer, line_buffer + line_start, new_start - line_start);
		used_bytes -= (new_start - line_start);

	}
}
#endif
