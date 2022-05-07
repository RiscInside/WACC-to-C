#!/bin/bash

VALID=$(find tests/valid/ regressions/valid/ -type f -name '*.wacc')
INVALID_SYN=$(find tests/invalid/syntaxErr/ regressions/invalid/syntaxErr/ -type f -name '*.wacc')
INVALID_SEM=$(find tests/invalid/semanticErr/ -type f -name '*.wacc')

FAILED=0
PASSED=0

for test in $VALID
do
    ./transpiler-opt $test &> /dev/null
    retVal=$?
    if [ $retVal -ne 0 ]; then
        echo Test $test fails
        FAILED=$((FAILED + 1))
    else
        PASSED=$((PASSED + 1))
    fi
done

for test in $INVALID_SYN
do
    ./transpiler-opt $test &> /dev/null
    retVal=$?
    if [ $retVal -ne 100 ]; then
        echo "Test $test should have failed with error 100 (got $retVal)"
        FAILED=$((FAILED + 1))
    else
        PASSED=$((PASSED + 1))
    fi
done

for test in $INVALID_SEM
do
    ./transpiler-opt $test &> /dev/null
    retVal=$?
    if [ $retVal -ne 200 ]; then
        echo "Test $test should have failed with code 200 (got $retVal)"
        FAILED=$((FAILED + 1))
    else
        PASSED=$((PASSED + 1))
    fi
done

echo failed $FAILED tests, passed $PASSED tests
