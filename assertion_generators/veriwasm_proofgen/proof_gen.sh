#!/usr/bin/env bash
# linking example

Help()
{
   echo "Illegal number of parameters."
   echo "This script run proof generation on a given file and a given function."
   echo "Generated proof and log are stored in the same directory as the source file."
   echo 
   echo "Usage: proof_gen.sh <file_name> <function_name>"
}

if [ "$#" -gt 2 ]; then
   Help
   exit 1
fi

echo "Building..."
cargo build

# Validates safety of native Wasm code

# USAGE:
#     veriwasm [FLAGS] [OPTIONS] -i <module path>

# FLAGS:
#         --disable-call-checks          
#         --disable-linear-mem-checks    
#         --disable-stack-checks         
#         --enable_zero_cost_checks      
#     -h, --help                         Prints help information
#         --strict                       
#     -V, --version                      Prints version information

# OPTIONS:
#         --arch <architecture>           Architecture of the executable (x64 | aarch64)
#     -c, --format <executable type>      Format of the executable (lucet | wasmtime)
#     -j, --jobs <jobs>                   Number of parallel threads (default 1)
#     -i <module path>                    path to native Wasm module to validate
#     -f, --func <one function>           Single function to process (rather than whole module)
#     -o, --output <stats output path>    Path to output stats file

if [ "$#" -eq 2 ]; then
   echo "Running verifier on module: [$1] function: [$2]"
   > log.prf

   # remove ' ' in $2, replace ',()' with '_'
   FUNC=$(echo $2 | tr -d ' ')
   FUNC=$(echo $FUNC | tr ',()' '_')
   echo $FUNC

   RUST_BACKTRACE=1 RUST_LOG=debug ../../target/debug/veriwasm -i $1 -f $2 &> $FUNC.log
   # RUST_BACKTRACE=1 RUST_LOG=debug ../../target/debug/veriwasm --disable-call-checks -i $1 -f "$2" &> $FUNC.log
   # RUST_BACKTRACE=1 RUST_LOG=debug ../../target/debug/veriwasm --disable-linear-mem-checks --disable-stack-checks --disable-call-checks -i $1 -f $2 &> $FUNC.log
   python3 postprocess.py log.prf log.prf

   DIR=$(dirname $1)
   FILE=$(basename $1)

   echo "Proof at ---- $DIR/$FUNC.prf"
   echo "Log at   ---- $DIR/$FUNC.log"
   mv log.prf $DIR/$FUNC.prf
   mv $FUNC.log $DIR/$FUNC.log
fi

if [ "$#" -eq 1 ]; then
   echo "Running verifier on whole module: [$1]"
   > log.prf
   
   DIR=$(dirname $1)
   FILE=$(basename $1)
   
   RUST_BACKTRACE=1 ../../target/debug/veriwasm -i $1 &> $FILE.log
   # RUST_BACKTRACE=1 ../../target/debug/veriwasm --disable-call-checks -i $1 &> $FILE.log
   python3 postprocess.py log.prf log.prf

   echo "Proof at ---- $DIR/$FILE.prf"
   echo "Log at   ---- $DIR/$FILE.log"
   mv log.prf $DIR/$FILE.prf
   mv $FILE.log $DIR/$FILE.log
fi
