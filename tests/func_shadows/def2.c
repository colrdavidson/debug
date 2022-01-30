static int shadow_test(short bar, short baz) {
	bar += 3;
	baz += 5;
	return bar + baz;
}

int extra_add(int foo) {
	return shadow_test(foo, foo) + 1;
}
