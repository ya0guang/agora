# How These Test Files are Generated

## Building WASM Binary

### Compile form C to WASM

```bash
wasm32-wasi-clang *.c [-O3] -o *.wasm
```

### Compile from WASM to X64 ELF

```bash
lucetc-wasi *.wasm -o *
```

## Building with fences

See doc: [as command mannual](https://man7.org/linux/man-pages/man1/as.1.html).

### Commands used with GCC

```sh
# Using gcc
gcc -S hello.c -O0 -o hello.s -Wa,-mlfence-after-load=yes

# or us as
~/Downloads/binutils-2.39/gas/as-new -mlfence-after-load=yes ./load.s -o load
```

The new version of binutils need to be built before:
```sh
wget https://ftp.gnu.org/gnu/binutils/binutils-2.39.tar.xz
tar -xvf binutils-2.39.tar.xz
cd binutils-2.39
./configure
make
```
