#!/bin/bash

VALID=$(find tests/valid/ regressions/valid/ extensions-tests/valid -type f -name '*.wacc')
INVALID_SYN=$(find tests/invalid/syntaxErr/ regressions/invalid/syntaxErr/ extensions-tests/invalid/syntaxErr/ -type f -name '*.wacc')
INVALID_SEM=$(find tests/invalid/semanticErr/ regressions/invalid/semanticErr/ extensions-tests/invalid/semanticErr/ -type f -name '*.wacc')

FAILED=0
PASSED=0

echo "Running valid tests..."
echo

for test in $VALID
do
    echo "Running transpiler on $test (./transpiler-opt $test $cFile)"
    cFile=$(mktemp /tmp/XXXXXX.c)
    binFile=$(mktemp /tmp/XXXXXX) 
    ./transpiler-opt $test $cFile
    retVal=$?
    if [ $retVal -ne 0 ]; then
        echo Test $test fails
        FAILED=$((FAILED + 1))
    else
        echo "Running gcc on $cFile (gcc -o $binFile $cFile)"
        gcc -o $binFile $cFile
        retVal=$?
        if [ $retVal -ne 0 ]; then
            echo Test $test fails on compilation
            FAILED=$((FAILED + 1))
        else
            PASSED=$((PASSED + 1))
        fi
    fi
done

echo "Running syntactically invalid tests..."
echo

for test in $INVALID_SYN
do
    echo "Running transpiler on $test (./transpiler-opt $test)"
    ./transpiler-opt $test
    retVal=$?
    echo
    if [ $retVal -ne 100 ]; then
        echo "Test $test should have failed with error 100 (got $retVal)"
        FAILED=$((FAILED + 1))
    else
        PASSED=$((PASSED + 1))
    fi
done

echo "Running semantically invalid tests..."
echo

for test in $INVALID_SEM
do
    echo "Running transpiler on $test (./transpiler-opt $test)"
    ./transpiler-opt $test
    retVal=$?
    echo
    if [ $retVal -ne 200 ]; then
        echo "Test $test should have failed with code 200 (got $retVal)"
        FAILED=$((FAILED + 1))
    else
        PASSED=$((PASSED + 1))
    fi
done

echo failed $FAILED tests, passed $PASSED tests
