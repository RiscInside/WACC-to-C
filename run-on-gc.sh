#!/bin/sh

path=$1
gcc_args=$2
c_output=$(mktemp /tmp/XXXXXX.c)
bin_output=$(mktemp /tmp/XXXXXX)
echo CGEN_BOEHM=1 ./transpiler-opt $path $c_output
CGEN_BOEHM=1 ./transpiler-opt $path $c_output
gcc -lgc -o $bin_output $c_output -ftrapv $gcc_args
$bin_output
