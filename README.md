
- [Agora Verifier](#agora-verifier)
  - [Getting Started](#getting-started)
    - [Requirments](#requirments)
    - [Build the Docker Image](#build-the-docker-image)
    - [Fast Trail](#fast-trail)
  - [Step-by-Step Guide](#step-by-step-guide)
    - [Dependencies](#dependencies)
    - [Reproducing the Verification Results](#reproducing-the-verification-results)
      - [SFI Policy Verification](#sfi-policy-verification)
        - [Verifiability](#verifiability)
        - [Reproducing Fig. 7 (Partial)](#reproducing-fig-7-partial)
          - [Generate the proof file](#generate-the-proof-file)
          - [Run Agora Verifier with Elapsed Time Recording](#run-agora-verifier-with-elapsed-time-recording)
          - [Run Agora Verifier and Calculate the SMT2 Constraints Size](#run-agora-verifier-and-calculate-the-smt2-constraints-size)
      - [IFC Policy Verification](#ifc-policy-verification)
        - [Introduction](#introduction)
        - [Results](#results)
    - [Reproducing the Smart Contract Results](#reproducing-the-smart-contract-results)
    - [Reproducing the TCB Size Calculation](#reproducing-the-tcb-size-calculation)

# Agora Verifier

## Getting Started

### Requirments

- Linux environment
- Docker, see [Docker Installation](https://docs.docker.com/get-docker/)

### Build the Docker Image

```bash
docker build -t agora .
```

### Fast Trail

```bash
docker run -it --rm agora
# Test the Agora Verifier ()
./test_verify_sfi_one.sh
# Test the smart contract
python3 ./test_smart_contract.py
```

## Step-by-Step Guide

### Dependencies

- Rust Nightly, see [Rust Installation](https://www.rust-lang.org/tools/install)
- Python 3.11 or later with necessary libraries
- `tokei`, for counting lines of code
  - install with `cargo install tokei`
- `cvc4`, as a sample solver
- SPEC 2006 benchmark suite
  - purchase & download from [SPEC 2006](https://www.spec.org/cpu2006/)

---

### Reproducing the Verification Results

**Note: due to copyright concern, SPEC 2006 benchmark (even the binary format) cannot be included in this repository. Please purchase the software.** Then place the compiled SPEC 2006 binaries under `resources/`.

#### SFI Policy Verification

##### Verifiability

- [Not recommanded] Run the script `./test_verify_sfi_all.sh` to reproduce the verification results for all SPEC 2006 benchmarks tested by us. This could take a long time to finish, so we would advice running several of the SPEC 2006 benchmarks instead.
  - **Note**: several functions may fail to verify due to the minor difference of the toolchains and too restrictive policies. The expected number of failed functions is below 5.
  - The verification results will be directly printed to the console.

##### Reproducing Fig. 7 (Partial)

This requires manually generating the proof (i.e., assertions), generating the constraints in SMT2 format, and then running the SMT solver to check the satisfiability of the constraints.

We use `libquantum_O0` as an example to demonstrate the the entire workflow. Again, the binary file should be placed under `resources/spec2006/`.


###### Generate the proof file

```sh
# Generate the proof file
pushd assertion_generators/wasm_sfi/
./proof_gen.sh ../../resources/spec2006/libquantum_O0 
popd
# Expected output:
# Proof at ---- ../../resources/spec2006/libquantum_O0.prf
# Log at   ---- ../../resources/spec2006/libquantum_O0.log
```

**Note:** the next two experiments assume the proof file `libquantum_O0.prf` is generated successfully.

###### Run Agora Verifier with Elapsed Time Recording

```sh
# The checker can run with or without optimization. Please use `features` in Rust to enable or disable the optimization.
# Default: optimized
# Baseline: unoptimized
# Local (in Fig 7b): mem_unhint, default
# Executing the proof checker and record the execution time
pushd checker

# Run the optimized version and record the time
time cargo run --release -- ../resources/spec2006/libquantum_O0 ../resources/spec2006/libquantum_O0.prf
# Elapsed time on an author's machine: 21.26s user 6.74s system 212% cpu 13.195 total

# Run the baseline version and record the time
time cargo run --release --features baseline -- ../resources/spec2006/libquantum_O0 ../resources/spec2006/libquantum_O0.prf
# This can be out of time on some machines!
# Elapsed time on an author's machine: 1748.05s user 24.13s system 132% cpu 22:18.37 total

# Run the local version and record the time
time cargo run --release --features mem_unhint,default -- ../resources/spec2006/libquantum_O0 ../resources/spec2006/libquantum_O0.prf
# Elapsed time on an author's machine: 46.04s user 8.68s system 288% cpu 18.945 total
```

###### Run Agora Verifier and Calculate the SMT2 Constraints Size

The commented lines are ignored.

```sh
# (Optimized) Generate the SMT2 constraints **WITHOUT** solving them
cargo run --release -- --solverless ../resources/spec2006/libquantum_O0 ../resources/spec2006/libquantum_O0.prf
find . -name '*.smt2' -type f -exec grep -hv '^\s*;' {} + | wc -l
# Expected output: 109005

# (Baseline, Unoptimized) Generate the SMT2 constraints **WITHOUT** solving them
cargo run --release --features baseline -- --solverless ../resources/spec2006/libquantum_O0 ../resources/spec2006/libquantum_O0.prf
find . -name '*.smt2' -type f -exec grep -hv '^\s*;' {} + | wc -l
# Expected output: 1414358
```

We observe a roughly 80% reduction in the size of the SMT2 constraints when using the optimized version of the Agora Verifier.

---

#### IFC Policy Verification

##### Introduction

For IFC policy verification, we have provided a script `verify_ifc.sh` to verify the IFC policies on several test files. The script will run the Agora Verifier with the IFC policy checker and generate the proof files. To avoid prolonged compilation time of the toolchain ConfLLVM, which requires compilation of the full LLVM framework, we have precompiled the binaries for the test files.

*Before running the script, please switch to the `ifc` branch of the repository.*

```bash
# Switch to the ifc branch
git switch ifc

# Run the script in the root directory to verify the IFC policies
./verify_ifc.sh

# Once you are done, you can switch back to the main branch
git switch main
```

##### Results

The script will verify the IFC policies on the following files:

- `resources/ifc/nginx/nginx.o`
- `resources/ifc/unit_test/test.o`
- `resources/ifc/unit_test/bad1.o`
- `resources/ifc/unit_test/bad2.o`

We keep the script simple and only print the verification results to the console. The output will look like below for nginx.o and test.o:

```bash
Running IFC policy checker on resources/ifc/nginx/nginx.o...
...
✔️  Function ngx_core_module_create_conf is tentatively verified ✔️
✔️  Function main is tentatively verified ✔️
✔️  Function ngx_exec_new_binary is tentatively verified ✔️
✔️  Function ngx_core_module_init_conf is tentatively verified ✔️
...
```

Whereas for the bad files, the output will look like below:

```bash
Running IFC policy checker on resources/ifc/unit_test/bad1.o...
❌  Error in verification of func matrix_multiply: guard: expect sat, but unsat ❌

Running IFC policy checker on resources/ifc/unit_test/bad2.o...
❌  Error in verification of func process_data: All assertion check: assertion failed ❌
```

As can be seen from the output, the Agora Verifier can successfully verify the IFC policies on the binaries compiled from ConfLLVM, and can also detect the violations of the IFC policies on the bad files.

The script will also show the differences between the test.o and bad1.o/bad2.o files, where we modify only one bit in the binary to violate the IFC policy. Specifically, for `bad1.o`, we modify the byte 0x5A8 from 0x03 to 0x13 to alter the magic sequence of the `matrix_multiply` function. For `bad2.o`, we modify the byte 0x56C in `process_data` function from 0x65 to 0x64. This changes the write destination of a secret source, making it write to the public memory segment instead of the secret memory segment.

Both of these modifications will cause the IFC policy checker to fail, as they violate the IFC policies defined in the ConfLLVM. You can refer to the assembly code `test.asm` for reference. The relative locations of the alternations are: 0x568 for `bad1.o` and 0x52c for `bad2.o`.

---

### Reproducing the Smart Contract Results

Please check the [readme file under `contracts` directory](./contracts/README.md) for details on how to reproduce the smart contract results.

### Reproducing the TCB Size Calculation

Please switch to the branch `tcbsize` for counting the TCB size. This version remove all unnecessary debug outputs and tests, and only keeps the necessary files for counting the TCB size.

You will find more details in the readme file under `tcbsize` branch.