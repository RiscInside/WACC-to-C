#!/bin/bash

VALID=$(find tests/valid/ -type f -name '*.wacc')
INVALID=$(find tests/invalid/syntaxErr/ -type f -name '*.wacc')

FAILED=0
PASSED=0

for test in $VALID
do
    if ! ./transpiler $test &> /dev/null; then
        echo Test $test fails
        FAILED=$((FAILED + 1))
    else
        PASSED=$((PASSED + 1))
    fi
done

for test in $INVALID
do
    if ./transpiler $test &> /dev/null; then
        echo Test $test should fail, but it does not
        FAILED=$((FAILED + 1))
    else
        PASSED=$((PASSED + 1))
    fi
done

echo failed $FAILED tests, passed $PASSED tests
