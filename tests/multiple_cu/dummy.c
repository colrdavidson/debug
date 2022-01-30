struct Foobar {
	int ret;
};

void super(int *);

int main(void) {
	struct Foobar foo = { .ret = 2 };
	foo.ret += 1;

	super(&foo.ret);

	int ret2;
	{
		int ret = 5;
		super(&ret);

		ret2 = ret;
	}

	return ret2 + foo.ret;
}
