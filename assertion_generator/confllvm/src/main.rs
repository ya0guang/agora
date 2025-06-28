pub mod dis;

use crate::dis::*;
use clap::Parser;
use iced_asm::{Instruction, InstructionInfoFactory, Mnemonic, Register};
use log::warn;
use ptir::*;
use semantics::semantics::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

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

    let mut proof_file = fs::File::create(&args.output_proof).unwrap();
    let magic = get_magic_sequences(&args.input_bin, &dis).unwrap();
    println!("{:?}", magic);
    for (idx, v) in magic.iter() {
        println!("{:x}: ", idx);
        println!("{:08b} || {:x}", v.first().unwrap(), v.first().unwrap());
        let num_str = format!("0x{:02x}", v.first().unwrap());
        write!(proof_file, "0x{:x}: {} {}\n", idx, "HINT MAGIC", num_str).unwrap();
    }

    let binary = fs::read(&args.input_bin).unwrap();
    // let sym_rawdata = resolve_text_symbols(&binary).unwrap();
    // for (k, v) in sym_rawdata.iter() {
    //     println!("{}: {:?}", k, v.data);
    // }

    // for (func, func_dis) in dis.iter() {
    //     println!("Function: {}", func);
    //     let cfg = cfg_analysis(binary.as_slice(), &func_dis).unwrap();
    //     println!("{:#x?}", cfg);
    // }

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

    let mut result = BTreeMap::new();

    for func_name in focused_functions.iter() {
        proofgen(&dis[func_name], &mut result);
        let cfg = cfg_analysis(binary.as_slice(), &dis[func_name]).unwrap();
        println!("{:x?}", cfg);

        // for (name, block) in dis.iter() {
        //     println!("Working on block {:0x?}", name);
        //     let block_addr = block.keys().min().unwrap();
        //     let target_addr = dis[func_name].keys().min().unwrap();
        //     if *block_addr == *target_addr {
        //         println!("Found the block");
        //         let num = magic.get(&(*target_addr - 16)).unwrap().first().unwrap();
        //         println!("{:08b} || {:x}", num, num);
        //         let num_str = format!("0x{:02x}", num);
        //         write!(
        //             proof_file,
        //             "0x{:x}: {} {}\n",
        //             target_addr - 16,
        //             "HINT MAGIC",
        //             num_str
        //         )
        //         .unwrap();
        //     }
        // }
        println!("Working on function {:0x?}", &dis[func_name].keys().min());
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
        print!("\n0x{:x}: {}", addr, ins);
        println!(" || {:?}", ins.flow_control());

        let proofs = proofmap.entry(*addr).or_insert_with(HashSet::new);
        let mut info_factory = InstructionInfoFactory::new();
        let info = info_factory.info(&ins);
        println!("{:?}", ins.mnemonic());
        println!("{:?}", info);

        match ins.mnemonic() {
            Mnemonic::Mov => {
                let dst = unalias_location(location_operand(ins, 0).unwrap()).unwrap();
                let src = expr_operand(ins, 1).unwrap();
                println!("dst: {:?}, src: {:?}", dst, src);
                let asgn = Assignment::new(dst, src);
                proofs.insert(Proof::Asgn(asgn));
                // if info.used_memory().is_empty() {
                //     let asgn = Assignment {
                //         lhs: Location::Register(ins.op_register(0)),
                //         rhs: Expr::Var(Location::Register(ins.op_register(1))),
                //     };
                //     proofs.insert(Proof::Asgn(asgn));
                // } else {
                //     println!("mem: {:?}", ins.memory_displ_size());
                //     info.used_memory()
                //         .iter()
                //         .for_each(|mem| match mem.access() {
                //             OpAccess::Read => {
                //                 let memcell = MemCell::try_from(mem.to_owned()).unwrap();
                //                 let asgn = Assignment {
                //                     lhs: Location::Register(ins.op_register(0)),
                //                     rhs: Expr::Var(Location::Memory(memcell)),
                //                 };
                //                 proofs.insert(Proof::Asgn(asgn));
                //             }
                //             OpAccess::Write => {
                //                 let memcell = MemCell::try_from(mem.to_owned()).unwrap();
                //                 let asgn = Assignment {
                //                     lhs: Location::Memory(memcell),
                //                     rhs: Expr::Var(Location::Register(ins.op_register(1))),
                //                 };
                //                 proofs.insert(Proof::Asgn(asgn));
                //             }
                //             _ => unimplemented!("unsupported memory access: {:?}", mem.access()),
                //         });
                // }
            }
            Mnemonic::Movsxd => {
                let dst = unalias_location(location_operand(ins, 0).unwrap()).unwrap();
                let src = expr_operand(ins, 1).unwrap();
                println!("dst: {:?}, src: {:?}", dst, src);
                let asgn = Assignment::new(dst, src);
                proofs.insert(Proof::Asgn(asgn));
            }
            Mnemonic::Add => {
                let dst = unalias_location(location_operand(ins, 0).unwrap()).unwrap();
                let src = expr_operand(ins, 1).unwrap();
                println!("dst: {:?}, src: {:?}", dst, src);
                let asgn = Assignment::new(
                    dst,
                    expr!(location_operand(ins, 0).unwrap().into(), bv!("bvadd"), src),
                );
                proofs.insert(Proof::Asgn(asgn));
            }
            Mnemonic::Sub => {
                let dst = unalias_location(location_operand(ins, 0).unwrap()).unwrap();
                let src = expr_operand(ins, 1).unwrap();
                println!("dst: {:?}, src: {:?}", dst, src);
                let asgn = Assignment::new(
                    dst,
                    expr!(location_operand(ins, 0).unwrap().into(), bv!("bvsub"), src),
                );
                proofs.insert(Proof::Asgn(asgn));
            }
            Mnemonic::Cmp => {
                let lhs = expr_operand(ins, 0).unwrap();
                let rhs = expr_operand(ins, 1).unwrap();
                println!("lhs: {:?}, rhs: {:?}", lhs, rhs);

                // CF
                proofs.insert(Proof::Asgn(Assignment::new(
                    Location::Flag(Flags::CF),
                    expr!(lhs.clone(), bv!("bvult"), rhs.clone()),
                )));

                // ZF
                proofs.insert(Proof::Asgn(Assignment::new(
                    Location::Flag(Flags::ZF),
                    expr!(lhs.clone(), bv!("="), rhs.clone()),
                )));

                // SF
                let sub = expr!(lhs.clone(), bv!("bvsub"), rhs.clone());
                let size = lhs.infer_sort().unwrap();
                let imm = match size {
                    Sort::BitVec(64) => Imm::new(1 << 63, ValSize::try_from(size).unwrap()),
                    Sort::BitVec(32) => Imm::new(1 << 31, ValSize::try_from(size).unwrap()),
                    Sort::BitVec(16) => Imm::new(1 << 15, ValSize::try_from(size).unwrap()),
                    Sort::BitVec(8) => Imm::new(1 << 7, ValSize::try_from(size).unwrap()),
                    _ => unimplemented!("unsupported size: {:?}", size),
                };
                let and = expr!(sub.clone(), bv!("bvand"), GenericExpr::Imm(imm));
                proofs.insert(Proof::Asgn(Assignment::new(
                    Location::Flag(Flags::SF),
                    expr!(GenericExpr::Imm(imm), bv!("="), and),
                )));

                // TODO implement OF
                // Maybe we don't need to model cmp and jcc instructions at all.
            }
            Mnemonic::Je => {
                let asgn = Assignment::new(
                    Register::RIP.into(),
                    Expr::Ite(
                        Box::new(Location::Flag(Flags::ZF).into()),
                        Box::new(Imm::from(ins.memory_displacement64()).into()),
                        Box::new(Imm::from(ins.next_ip()).into()),
                    ),
                );
                proofs.insert(Proof::Asgn(asgn));
            }
            Mnemonic::Jne => {
                let asgn = Assignment::new(
                    Register::RIP.into(),
                    Expr::Ite(
                        Box::new(Location::Flag(Flags::ZF).into()),
                        Box::new(Imm::from(ins.next_ip()).into()),
                        Box::new(Imm::from(ins.memory_displacement64()).into()),
                    ),
                );
                proofs.insert(Proof::Asgn(asgn));
            }
            _ => (),
        }
    }
    result
}
