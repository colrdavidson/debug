#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

int main(int argc, char **argv) {
	int pid = fork();
	if (pid == 0) {
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execvp(argv[1], argv + 1);
		return -1;
	}

	uint64_t instruction_count = 0;
	for (;;) {
		int status;
		wait(&status);
		if (WIFEXITED(status)) {
			return 1;
		}

		struct user_regs_struct regs;

		ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		printf("Instruction Count: %lu\n", instruction_count);
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

		ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
		instruction_count++;

		usleep(500000);
	}

	return 0;
}
