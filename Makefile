VALID_TESTS = $(shell find tests/valid/ -type f -name '*.flac')

all: transpiler-dbg transpiler-opt

transpiler-opt: transpiler.c
	gcc -o transpiler-opt transpiler.c -O3 -Wall -Werror -Wextra

transpiler-dbg: transpiler.c
	gcc -o transpiler-dbg transpiler.c -Wall -Werror -Wextra -g

tests:
	git clone "https://gitlab.doc.ic.ac.uk/lab2122_spring/wacc_examples/" examples
	mkdir tests
	mv examples/invalid tests/invalid
	mv examples/valid tests/valid
	rm -rf examples

run-tests: transpiler-opt
	./run-tests.sh
