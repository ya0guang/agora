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

### Reproducing the Smart Contract Results

Please check the [readme file under `contracts` directory](./contracts/README.md) for details on how to reproduce the smart contract results.

### Reproducing the TCB Size Calculation

Please switch to the branch `tcbsize` for counting the TCB size. This version remove all unnecessary debug outputs and tests, and only keeps the necessary files for counting the TCB size.

You will find more details in the readme file under `tcbsize` branch.
