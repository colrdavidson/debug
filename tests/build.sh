for dir in $(find . -mindepth 1 -maxdepth 1 -type d)
do
	cd "$dir"
	echo "Building $dir"
	./build.sh
	cd - > /dev/null
done
