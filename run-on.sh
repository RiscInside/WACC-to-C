#!/bin/sh

path=$1
gcc_args=$2
c_output=$(mktemp /tmp/XXXXXX.c)
bin_output=$(mktemp /tmp/XXXXXX)
./transpiler-opt $path $c_output
gcc -o $bin_output $c_output -ftrapv $gcc_args
$bin_output
