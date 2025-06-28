#!/bin/bash
# This script is used to verify the integrity of the IFC policy in the Agora project.
# It runs the IFC policy checker on a specific binary and generates assertions based on the policy.

# Usage: ./verify_ifc.sh
# Ensure that the script is run from the correct directory
# and that the necessary resources are available in the specified paths.
# Change to the directory where the script is located
cd "$(dirname "$0")/../agora" || exit 1

# collect the files in resources/ifc/nginx and resources/ifc/test into a list
ifc_files=(
    "resources/ifc/nginx/nginx.o"
    "resources/ifc/unit_test/test.o"
    "resources/ifc/unit_test/bad1.o"
    "resources/ifc/unit_test/bad2.o"
)

# Iterate over each file and run the IFC policy checker
for file in "${ifc_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo "Running IFC policy checker on $file..."
        cargo run --bin confverify -- "$file" > output.log 2>&1
        sed -i '/HINT MAGIC/!d' output.prf
        RUST_LOG=off cargo run --bin checker -- -p ifc -b elf ${file} output.prf 
        echo
        echo "----------------------------------------"
        echo 
    fi
done

# remove generated .log files and .smt2 files
rm -f *.log *.smt2 *.prf


# show diff of test.o and bad1.o/bad2.o
cd resources/ifc/unit_test || exit 1
echo "Diff between test.o and bad1.o:"
cmp -l test.o bad1.o | gawk '{printf "%08X %02X %02X\n", $1-1, strtonum(0$2), strtonum(0$3)}'

echo "Diff between test.o and bad2.o:"
cmp -l test.o bad2.o | gawk '{printf "%08X %02X %02X\n", $1-1, strtonum(0$2), strtonum(0$3)}'