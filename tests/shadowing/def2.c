static int shadow_test(int bar) {
	bar += 3;
	return bar;
}

int extra_add(int foo) {
	return shadow_test(foo) + 1;
}
