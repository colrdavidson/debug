typedef struct {
	int apple;
	char carrot;
	int banana;
	short beet;
} Foobar;

struct BigStruct {
	long long f1;
	long long f2;
	long long f3;
	long long f4;
	long long f5;
	long long f6;
	long long f7;
	long long f8;
};

int main() {
	struct BigStruct bs = {0};

	Foobar foo = {0};
	foo.apple = 2;
	foo.banana = 5;
	foo.beet = 9;
	foo.carrot = 5;
	foo.beet += bs.f8;

	foo.apple += foo.banana;
	foo.banana += foo.apple;
	bs.f3 -= foo.carrot;

	return foo.apple + foo.banana + foo.beet + foo.carrot + bs.f3 + bs.f8;
}
