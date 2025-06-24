use clap::Parser;
use disasm::disasm_binary;
use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess};
use lazy_static::lazy_static;
use log::warn;
use ptir::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

// These instructions don't need to be fenced after
lazy_static! {
    pub static ref AVOID_FENCE_AFTER: HashSet<Mnemonic> = {
        let mut set = HashSet::new();
        set.insert(Mnemonic::Ret);
        set.insert(Mnemonic::Call);
        set.insert(Mnemonic::Pop);
        set.insert(Mnemonic::Lfence);
        set.insert(Mnemonic::Leave);
        set
    };
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Args {
    /// The input path of binary ELF file
    #[clap(value_parser)]
    input_bin: PathBuf,
    /// The output path of proof file
    #[clap(value_parser, default_value = "output.prf")]
    output_proof: PathBuf,
    /// Specify the only function work on
    #[clap(short, long, value_parser)]
    focused_functions: Option<Vec<String>>,
    /// Specify the functions that are avoided
    #[clap(short, long, value_parser)]
    avoid_functions: Option<Vec<String>>,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let dis = disasm_binary(&args.input_bin).unwrap();

    // filter out unfocused functions
    let mut focused_functions: BTreeSet<String> = match args.focused_functions {
        Some(func_names) => {
            // ensure that function names are in the ELF
            func_names.iter().for_each(|k| {
                if !dis.contains_key(k) {
                    panic!("focused function {} not found", k)
                }
            });
            BTreeSet::from_iter(func_names)
        }
        None => dis.keys().cloned().collect(),
    };

    // filter out avoid functions
    for func_name in args.avoid_functions.unwrap_or_default() {
        if !focused_functions.remove(&func_name) {
            warn!("avoided function {} not found", func_name)
        }
    }

    let mut proof_file = fs::File::create(&args.output_proof).unwrap();
    // let mut proof_map = HashMap::new();
    let mut result = BTreeMap::new();
    for func_name in focused_functions.iter() {
        proofgen(&dis[func_name], &mut result);
    }
    for (addr, proofs) in result {
        for p in proofs {
            write!(proof_file, "0x{:x}: {}\n", addr, p.output_prf()).unwrap();
        }
    }
}

fn proofgen(
    dis: &BTreeMap<u64, Instruction>,
    proofmap: &mut BTreeMap<u64, HashSet<Proof>>,
) -> Vec<(u64, Proof)> {
    let result = Vec::new();
    for (addr, ins) in dis {
        let proofs = proofmap.entry(*addr).or_insert_with(HashSet::new);
        let mut info_factory = InstructionInfoFactory::new();
        let info = info_factory.info(&ins);
        let asgn = if ins.mnemonic() == Mnemonic::Lfence {
            Assignment {
                lhs: Location::MAS(MicroArchitecturalState::LoadBuffer),
                rhs: Expr::Const(Const::new(Sort::Bool, "false".to_string())),
            }
        } else if !AVOID_FENCE_AFTER.contains(&ins.mnemonic())
            && info.used_memory().iter().any(|mem| {
                // println!("mem access: {:?} @ 0x{:x}", mem.access(), addr);
                match mem.access() {
                    // check if it's a memory load instruction
                    OpAccess::Read
                    | OpAccess::CondRead
                    | OpAccess::ReadCondWrite
                    | OpAccess::ReadWrite => true,
                    _ => false,
                }
            })
        {
            Assignment {
                lhs: Location::MAS(MicroArchitecturalState::LoadBuffer),
                rhs: Expr::Const(Const::new(Sort::Bool, "true".to_string())),
            }
        } else {
            continue;
        };
        proofs.insert(Proof::Asgn(asgn));
    }
    result
}
