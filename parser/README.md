# Proof Parser

Example of the proof:

```

0x1000 rsp := rsp - 8
0x1000 rsp <= 0x40000

```

## Kind of Proofs

- Assignment `asgn`, e.g.: (`[var] := [expr]`): partial semantics
- Relationship `rel`, e.g.: (`[expr1] <> [expr2]`): derived directly from the semantics
- Hint `hint`, `HINT rel`): policy-related hints, must be checked for unsat first to be used as assumption
- Annotation, e.g.: (`<INV> : [rel]` and `<branch> : [label] [rel]`)

## Proof Format

In this simple grammer, "[]" is used to represent non-terminal.

```
location := line in disassembled binary
var := registers | memory_loc | flags
expr := imm | var | [binop] expr expr | [unop] expr 
Assignment := "[var] := [expr]"
Relationship := "[rel] [expr] [expr]"
annotation_type := INV | branch 
Annotation := "<[kind]> : [Relationship]"
line := "[location] : [Assignment] | [Relationship] | [Annotation]"
proof := (line :: delimiter)*
```
