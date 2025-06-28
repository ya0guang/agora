# Agora Verifier

## Getting Started

### Requirements

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

### Reproducing the TCB Size Report

Run `tokei` to count lines of code. These components correspond to the TCB size report in the paper (Table 1). There are some minor differences in some numbers, such as the total count of BV or the line count of IFC-ConfVERIFY, due to recent updates. The overall numbers are still very close to the original table in the paper.

```bash
tokei FILE_NAME
```

| Table 1 Items          | Counted Files                                       | LoC Sum                             |
| ---------------------- | --------------------------------------------------- | ----------------------------------- |
| General Utilities      | `ir/`,  `checker/[semantics, ssa, dis, policy/mod]` | 1820 + 507 + 692 + 415 + 241 = 3675 |
| Binary Verifier        | `checker/[validate, solve, main]`                   | 188 + 468 + 123 = 779               |
| Policy: SFI-VeriWASM   | `checker/policy/wasmsfi`                            | 623                                 |
| Policy: LVI            | `checker/policy/lvi`                                | 77                                  |
| Policy: IFC-ConfVERIFY | `checker/policy/ifc`                                | 324                                 |
