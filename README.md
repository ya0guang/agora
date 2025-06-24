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

1. Place the compiled SPEC 2006 binaries under `resources/`
2. Run the script `./test_verify_sfi_all.sh`

The verification should pass.

### Reproducing the Smart Contract Results

Please check the [readme file under `contracts` directory](./contracts/README.md) for details on how to reproduce the smart contract results.

### Reproducing the TCB Size Calculation

Please switch to the branch `tcbsize` for counting the TCB size. This version remove all unnecessary debug outputs and tests, and only keeps the necessary files for counting the TCB size.

You will find more details in the readme file under `tcbsize` branch.
