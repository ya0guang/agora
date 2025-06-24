#! /usr/bin/env python3

import os
import subprocess

# Specify the config files and tasks to iterate over
config_files = {"lucet_wasm": "O0", "lucet_wasm_o3": "O3"}
tasks = [
    "401.bzip2",
    "473.astar",
    "445.gobmk",
    "464.h264ref",
    "470.lbm",
    "462.libquantum",
    "429.mcf",
    "433.milc",
    "444.namd",
    "453.povray",
    "458.sjeng",
    "450.soplex",
    "482.sphinx3",
]
# tasks = ["401.bzip2"]
# bzip gobmk h264ref lbm libquantum mcf milc namd povray sjeng soplex sphinx3

# Clang may not compile some code due to minor bugs
# Known bugs:
# 1. astar: Library.cpp change ""PRId64"" to "lld"
# 2. povray: undeclared symbol "getcwd", "chdir"
# 3. sjeng: sjeng.c comment out line 476
# 4. soplex: mpsinput.cc comment out line 75, 76; Linker cannot find symbol "__cxa_throw"
# 5. sphinx3: linker cannot find symbol "unlimit", "popen", "pclose", "getcwd"

spec_2006_path = "{SPEC_PATH}"
project_path = "{PROJECT_PATH}"

# Specify the pathes
env_file = spec_2006_path + "/shrc"
spec_dir = spec_2006_path
copy_dst = project_path + "/resources/fence/"

# Loop over the config files
for config, suffix in config_files.items():
    # Loop over the tasks
    for task in tasks:
        # Load the environment variables
        subprocess.run([".", env_file], shell=True)

        # Enter the build directory and run specmake
        os.chdir(spec_dir)
        result = subprocess.run(
            [
                "runspec --fake --loose --size test --tune base --config "
                + config
                + " "
                + task
            ],
            shell=True,
            capture_output=True,
            text=True,
        )
        os.chdir(spec_dir + "benchspec/CPU2006/" + task)
        print("Debug: pwd: " + os.getcwd())
        os.chdir("build/build_base_" + config + ".0000")
        subprocess.run(["specmake clean"], shell=True)
        subprocess.run(["specmake"], shell=True)

        task_name = task.split(".")[1]
        task_filename = task_name + "_" + suffix
        wasm_filename = task_filename + ".wasm"

        subprocess.run(["mv " + task_name + " " + wasm_filename], shell=True)

        # compile the lucet ELF
        subprocess.run(
            ["lucetc-wasi " + wasm_filename + " -o " + task_name], shell=True
        )

        # move the files to the project directory
        subprocess.run(
            ["cp " + wasm_filename + " " + copy_dst + wasm_filename], shell=True
        )
        subprocess.run(["cp " + task_name + " " + copy_dst + task_filename], shell=True)
