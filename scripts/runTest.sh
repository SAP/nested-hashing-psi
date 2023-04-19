#!/bin/bash
echo "Running test with parameters:"
echo "Server Set Size:  $1"
echo "Key Length:  $2"
echo "Index to compare:  $3 "
echo "Element differs: $4"

../build/tests/TestServer $1 $2 & 
../build/tests/TestClient $1 $2 $3 $4

echo "Done"