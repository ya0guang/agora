#!/usr/bin/env bash
binaries=(
    resources/spec2006/libquantum_O3
)

for binary in ${binaries[@]}
do
    python3 eval/run_workflow.py --no-build -e $binary
    if [ $? -ne 0 ]; then
        exit $?
    fi
done