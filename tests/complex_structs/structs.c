typedef struct {
	int apple;
	int carrot;
	int beet;
	int banana;
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

typedef struct {
	Foobar bar;
	int baloney;
} Structification;

int main() {
//	struct BigStruct bs = {0};

	Structification stuckt = {0};
	stuckt.bar.banana = 2;
	stuckt.bar.beet = 8;
	stuckt.bar.banana += stuckt.bar.beet;
/*
	foo.banana = 5;
	foo.beet = 9;
	foo.carrot = 5;
	foo.beet += bs.f8;

	foo.apple += foo.banana;
	foo.banana += foo.apple;
	bs.f3 -= foo.carrot;
*/

	return stuckt.bar.beet + stuckt.bar.apple;
//	return foo.apple + foo.banana + foo.beet + foo.carrot + bs.f3 + bs.f8;
}
