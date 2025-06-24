#!/usr/bin/env bash
binaries=(
    resources/spec2006/astar_O0
    resources/spec2006/astar_O3
    resources/spec2006/bzip2_O0
    resources/spec2006/bzip2_O3
    resources/spec2006/gobmk_O0
    resources/spec2006/gobmk_O3
    resources/spec2006/h264ref_O0
    resources/spec2006/h264ref_O3
    resources/spec2006/lbm_O0
    resources/spec2006/lbm_O3
    resources/spec2006/libquantum_O0
    resources/spec2006/libquantum_O3
    resources/spec2006/mcf_O0
    resources/spec2006/mcf_O3
    resources/spec2006/milc_O0
    resources/spec2006/milc_O3
    resources/spec2006/namd_O0
    resources/spec2006/namd_O3
    resources/spec2006/sjeng_O0
    resources/spec2006/sjeng_O3
)

for binary in ${binaries[@]}
do
    python3 eval/run_workflow.py --no-build -e $binary
    if [ $? -ne 0 ]; then
        exit $?
    fi
done