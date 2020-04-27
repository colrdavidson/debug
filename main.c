#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

uint64_t inject_breakpoint_at_addr(int pid, uint64_t addr) {
	uint64_t orig_data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);

	// Replace first byte of code at address with int 3
	uint64_t data_with_trap = (orig_data & 0xFFFFFFFFFFFF00) | 0xCC;
	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data_with_trap);

	return orig_data;
}

void repair_breakpoint(int pid, uint64_t addr, uint64_t orig_data) {
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);

	ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)orig_data);
	regs.rip -= 1;
	ptrace(PTRACE_SETREGS, pid, NULL, &regs);
}

int jump_to_next_breakpoint(int pid) {
	ptrace(PTRACE_CONT, pid, NULL, NULL);

	int status;
	wait(&status);
	if (!WIFSTOPPED(status)) {
		printf("Failure to break on breakpoint\n");
		exit(1);
	}

	return 0;
}

int main(int argc, char **argv) {
	int pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(argv[1], argv + 1);
		return -1;
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

	repair_breakpoint(pid, break_addr, orig_data);
	ptrace(PTRACE_CONT, pid, NULL, NULL);

	return 0;
}
