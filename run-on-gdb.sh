#!/bin/sh

path=$1
gcc_args=$2
c_output=$(mktemp /tmp/XXXXXX.c)
bin_output=$(mktemp /tmp/XXXXXX)
CGEN_LINE_CONTROL=1 ./transpiler-opt $path $c_output
gcc -o $bin_output $c_output -ftrapv -g $gcc_args
gdb $bin_output
