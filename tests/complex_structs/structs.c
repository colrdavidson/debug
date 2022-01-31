typedef struct {
	int apple;
	char carrot;
	int banana;
	short beet;
} Foobar;

int main() {
	Foobar foo = {0};
	foo.apple = 2;
	foo.banana = 5;
	foo.beet = 9;
	foo.carrot = 5;

	foo.apple += foo.banana;
	foo.banana += foo.apple;

	return foo.apple + foo.banana + foo.beet + foo.carrot;
}
