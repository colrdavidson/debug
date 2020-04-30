#include <stdio.h>

typedef struct {
	int ret;
} foobar;

int main(void) {
	printf("Hello World!\n");

	foobar foo;
	foo.ret = 2;

	return foo.ret;
}
