#include <stdio.h>

void super(int *);

int main(void) {
	printf("Hello World!\n");

	int ret = 2;

	super(&ret);

	return ret;
}
