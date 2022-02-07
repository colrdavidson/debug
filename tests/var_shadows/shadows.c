int main() {
	int foo = 502;
	int bar = 3;

	{
		int bar = 5;
		foo += bar;
		bar += 1;
		foo += bar;
	}

	return foo;
}
