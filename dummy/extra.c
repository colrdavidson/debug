#include <stdio.h>

void super(int *data) {
	int foo = 2;
	*data += 1 + foo;
	printf("Yay");
}
