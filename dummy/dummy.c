#include <stdio.h>

void super(void);

typedef struct {
	int ret;
} foobar;

int main(void) {
	printf("Hello World!\n");

	foobar foo;
	foo.ret = 2;

	super(&foo.ret);

	return foo.ret;
}
