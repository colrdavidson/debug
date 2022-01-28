void super(int *);

int main(void) {

	int ret = 0;
	int ret2 = 0;

	super(&ret);

	{
		int ret = 5;
		super(&ret);

		ret2 = ret;
	}

	return ret + ret2;
}
