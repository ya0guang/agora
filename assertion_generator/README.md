# Using the PoC Proof Generators

## Known Bugs

### Switch Table Problem

`iced` is just an disassembler. It cannot identify the switch table embedded inside the code block. Reverse engineering frameworks can deal with this case.

#### Scope

- mcf_O0: `vfscanf_95`, `pop_arg_60`, `__wasilibc_find_relpath_66`, `memcpy_106`, `dual_feasible_20`, `__wasilibc_find_relpath_66`, `fcntl_69`, `scanexp_94`, `__floatscan_93`, `printf_core_59`, `__wasilibc_populate_libpreopen_68`

Solutions:

1. Avoid generating switch table try `-fno-switch-tables`
2. Mark the switch tables in another way
3. Switch to another disassembling framework

### Floating point register

The CTx FP registers are of 80 bits!!!! Which is a very ugly thing.
