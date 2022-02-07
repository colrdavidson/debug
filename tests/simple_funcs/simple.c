void test_func(int *a) {
	*a += 3;
}

int main() {
	int foo = 0;
	test_func(&foo);
	test_func(&foo);
	return foo;
}
