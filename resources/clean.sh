#!/bin/bash

echo
echo "Cleaning verification files..."

# remove all .prf files in spec2006
echo
echo "Removing all .prf files in spec2006..."
find ./spec2006 -name "*.prf" -type f -print -delete

# remove all .log files
echo
echo "Removing all .log files..."
find ./spec2006 -name "*.log" -type f -print -delete
find ../ -name "*.log" -type f -print -delete

# remove all .smt2 files in checker
echo
echo "Removing all .smt2 files in checker..."
find ../checker -name "*.smt2" -type f -print -delete
