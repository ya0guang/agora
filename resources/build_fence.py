#! /usr/bin/env python3

import os
import subprocess

# Specify the config files and tasks to iterate over
config_files = {"lfence": "O0", "lfence_O3": "O3"}
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
            ["runspec --fake --loose --tune base --config " + config + " " + task],
            shell=True,
            capture_output=True,
            text=True,
        )
        print(result.stdout)
        os.chdir(spec_dir + "benchspec/CPU2006/" + task)
        print("Debug: pwd: " + os.getcwd())
        os.chdir("build/build_base_" + config + ".0000")
        subprocess.run(["specmake clean"], shell=True)
        subprocess.run(["specmake"], shell=True)

        task_name = task.split(".")[1]
        task_filename = task_name + "_" + suffix

        subprocess.run(["cp " + task_name + " " + copy_dst + task_filename], shell=True)
