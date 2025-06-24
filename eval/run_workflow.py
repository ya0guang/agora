#!/usr/bin/env python3
import argparse
import os
import pathlib
import shutil
import subprocess
import sys


def get_path(binary: pathlib.Path, basepath: pathlib.Path = None):
    parent = binary.parent if basepath is None else basepath
    name = binary.name
    proof = parent / f'{name}.prf'
    log = parent / f'{name}.log'
    disasm = parent / f'{name}.json'
    proof_time_cost = parent / f'time-proof.json'
    checker_time_cost = parent / f'time-checker.json'
    return proof, log, disasm, proof_time_cost, checker_time_cost


def build():
    print('[*] Building...')
    ret = os.system('cargo build')
    if ret != 0:
        print('[!] Build failed')
        exit(1)
    print('[+] Build completed')


def touch(path):
    file = open(path, 'w')
    file.close()


def gen_proof(basepath: pathlib.Path, binary: pathlib.Path, proof: pathlib.Path, log: pathlib.Path, time_cost: pathlib.Path):
    print(f'[*] Generating proof for [{binary}]...')
    touch('log.prf')
    veriwasm = basepath / 'target/debug/veriwasm'
    postprocess = basepath / 'assertion_generators/wasm_sfi/postprocess.py'
    # ret = os.system(f'{veriwasm} --disable-call-checks -i {binary} &> {log}')
    if log is not None:
        log_file = open(log, 'w')
        ret = subprocess.call([veriwasm, '-i', binary, '1', time_cost], stdout=log_file, stderr=log_file)
    else:
        ret = subprocess.call([veriwasm, '-i', binary, '1', time_cost])
    if ret != 0:
        print('[!] Proof generation failed')
        exit(1)
    # ret = os.system(f'python3 {postprocess} log.prf log.prf')
    ret = subprocess.call(['python3', postprocess, 'log.prf', 'log.prf'])
    if ret != 0:
        print('[!] Proof postprocess failed')
        exit(1)
    shutil.move('log.prf', proof)
    print(f'[+] Proof saved at {proof}')
    print(f'[+] Log saved at {log}')


def gen_disasm(basepath: pathlib.Path, binary: pathlib.Path, disasm: pathlib.Path):
    print(f'[*] Generating disassembly json for [{binary}]...')
    disasm_exe = basepath / 'target/debug/disasm'
    # ret = os.system(f'{disasm_exe} {binary} {disasm}')
    ret = subprocess.call([disasm_exe, binary, disasm])
    if ret != 0:
        print('[!] Disassembly generation failed')
        exit(1)
    print(f'[+] Disassembly json saved at {disasm}')


def run_checker(
        basepath: pathlib.Path,
        binary: pathlib.Path,
        proof: pathlib.Path,
        disasm: pathlib.Path,
        avoids: list[str],
        focus: str,
        threads: int,
        cost_time: pathlib.Path,
        solverless: bool,
        ):
    print(f'[*] Executing the proof checker for [{binary}]...')
    checker = basepath / 'target/debug/checker'
    opts = ["-a", "lucet_probestack"]
    if solverless:
        opts.append('--solverless')
    for func in avoids:
        opts.append('-a')
        opts.append(func)
    for func in focus:
        opts.append('-f')
        opts.append(func)
    if threads is not None:
        opts.append('-t')
        opts.append(str(threads))
    # ret = os.system(f'{checker} {binary} {proof} {' '.join(opts)}')
    ret = subprocess.call([checker, binary, proof, cost_time] + opts)
    if ret != 0:
        print('[!] Proof check failed')
        exit(1)
    print('[+] Proof check completed')


def main():
    parser = argparse.ArgumentParser(description='Generate proof/disasm and run cheker for a given binary')
    parser.add_argument('binary', type=pathlib.Path,
                        help='the path to the binary')
    parser.add_argument('--no-build', action='store_true',
                        help='whether to exclude the build process (default: False)')
    parser.add_argument('--no-proof-gen', action='store_true',
                        help='whether to exclude the generation of the proof file (default: False)')
    parser.add_argument('--no-disasm-gen', action='store_true',
                        help='whether to exclude the generation of the disasm file (default: False)')
    parser.add_argument('--no-check', action='store_true',
                        help='whether to run the proof checker (default: False)')
    parser.add_argument('--remove-smt', action='store_true',
                        help='whether to remove the smt2 files after the proof check (default: False)')
    parser.add_argument('--solverless', action='store_true')
    parser.add_argument('-a', '--avoid-functions', nargs='*', metavar='func', default=[],
                        help='the functions to be avoided')
    parser.add_argument('-f', '--focused-functions', nargs='*', metavar='func', default=[],
                        help='the functions to be focused')
    parser.add_argument('-e', '--generated-in-eval', action='store_true',
                        help='whether to save the generated resources in `eval` directory (default: False)')
    parser.add_argument('-t', '--threads', nargs='?', type=int,
                        help='the number of threads to be used in the chcker')
    args = parser.parse_args()

    basepath = pathlib.Path(sys.path[0]).parent
    binary = pathlib.Path(os.getcwd()) / args.binary
    basename = args.binary.name

    if args.generated_in_eval:
        evalpath = basepath / 'eval' / basename
        if not evalpath.exists():
            os.makedirs(evalpath)
        os.chdir(evalpath)
        proof, log, disasm, proof_time_cost, checker_time_cost = get_path(binary, evalpath)
    else:
        proof, log, disasm, proof_time_cost, checker_time_cost = get_path(binary)

    if not args.no_build:
        build()
    
    if not args.no_proof_gen:
        gen_proof(basepath, binary, proof, log, proof_time_cost)

    if not args.no_disasm_gen:
        gen_disasm(basepath, binary, disasm)

    if not args.no_check:
        run_checker(basepath, binary, proof, disasm, args.avoid_functions, args.focused_functions, args.threads, checker_time_cost, args.solverless)
        if args.remove_smt:
            os.system('rm *.smt2')


if __name__ == '__main__':
    main()
