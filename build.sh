clang -O3 -g -static -Wall -Wextra -Wno-unused-function -o debugger main.c
clang -O3 -Wall -Wextra -o gui gui_main.c -lSDL2 -lGL
