while [[ $# -gt 0 ]]; do
	case $1 in
		-l|--local)
# Shuts off network stack, runs local command processing only
			LOCAL="-D LOCAL"
			shift
		;;
		*)
			shift
		;;
	esac
done

clang -Os -g $LOCAL -Wall -Wextra -o debugger main.c

cd tests
./build.sh
