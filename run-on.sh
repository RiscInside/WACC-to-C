#!/bin/sh

path=$1
c_output=$(mktemp /tmp/XXXXXX.c)
bin_output=$(mktemp /tmp/XXXXXX)
./transpiler-opt $path $c_output
gcc -o $bin_output $c_output -ftrapv
$bin_output
