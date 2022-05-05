VALID_TESTS = $(shell find tests/valid/ -type f -name '*.flac')

transpiler: transpiler.c
	gcc -o transpiler transpiler.c -Wall -Werror -Wextra -g

tests:
	git clone "https://gitlab.doc.ic.ac.uk/lab2122_spring/wacc_examples/" examples
	mkdir tests
	mv examples/invalid tests/invalid
	mv examples/valid tests/valid
	rm -rf examples

run-tests: transpiler tests
	./run-tests.sh
