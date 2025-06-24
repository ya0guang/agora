mod call_analyzer;
mod heap_analyzer;
mod jump_analyzer;
pub mod locals_analyzer;
pub mod reaching_defs;
mod stack_analyzer;
use crate::ir;
use crate::ir::types::{
    Binopcode, IRBlock, IRMap, MemArg, MemArgs, Stmt, Unopcode, ValSize, Value,
};
use crate::lattices::reachingdefslattice::LocIdx;
use crate::lattices::{Lattice, VarState};
use iced_asm::Register;
use parser::parse_proof_str;

use ptir::{Assignment, Expr, Flags, Imm, MemCell, MemCellBuilder, OutputPrf, Proof, Relationship};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::prelude::*;
use yaxpeax_core::analyses::control_flow::VW_CFG;

/*     Public API     */
pub use self::call_analyzer::CallAnalyzer;
pub use self::heap_analyzer::HeapAnalyzer;
pub use self::jump_analyzer::SwitchAnalyzer;
pub use self::stack_analyzer::StackAnalyzer;

pub type AnalysisResult<T> = HashMap<u64, T>;
pub type ProofMap = HashMap<u64, Vec<Proof>>;

pub fn args_to_var(args: &MemArgs) -> MemCell {
    match args {
        MemArgs::Mem1Arg(arg1) => match arg1 {
            MemArg::Reg(reg, size) => MemCellBuilder::new()
                .base_reg(reg_to_reg(*reg, *size).unwrap())
                .build(),
            MemArg::Imm(_, _, _) => panic!("Invalid argument, should not happen."),
        },
        MemArgs::Mem2Args(arg1, arg2) => {
            let mem = match arg1 {
                MemArg::Reg(reg1, size1) => match arg2 {
                    MemArg::Reg(reg2, size2) => MemCellBuilder::new()
                        .base_reg(reg_to_reg(*reg1, *size1).unwrap())
                        .index_reg(reg_to_reg(*reg2, *size2).unwrap())
                        .scale(Some(1u8)),
                    MemArg::Imm(sign, size2, val) => MemCellBuilder::new()
                        .base_reg(reg_to_reg(*reg1, *size1).unwrap())
                        .displacement(*val),
                },
                MemArg::Imm(_, _, _) => panic!("Invalid argument, should not happen."),
            };
            mem.build()
        }
        MemArgs::Mem3Args(arg1, arg2, arg3) => {
            let mem = match arg1 {
                MemArg::Reg(reg1, size1) => match arg2 {
                    MemArg::Reg(reg2, size2) => match arg3 {
                        MemArg::Imm(sign, size3, val) => MemCellBuilder::new()
                            .base_reg(reg_to_reg(*reg1, *size1).unwrap())
                            .index_reg(reg_to_reg(*reg2, *size2).unwrap())
                            .scale(Some(1u8))
                            .displacement(*val),
                        _ => panic!("Invalid argument, should not happen."),
                    },
                    _ => panic!("Invalid argument, should not happen."),
                },
                _ => panic!("Invalid argument, should not happen."),
            };
            mem.build()
        }
        MemArgs::MemScale(arg1, arg2, imm) => {
            if let (MemArg::Reg(reg1, size1), MemArg::Reg(reg2, size2), MemArg::Imm(_, _, val)) =
                (arg1, arg2, imm)
            {
                MemCellBuilder::new()
                    .base_reg(reg_to_reg(*reg1, *size1).unwrap())
                    .index_reg(reg_to_reg(*reg2, *size2).unwrap())
                    .scale(Some(*val as u8))
                    .build()
            } else {
                panic!("not supported scale format")
            }
        }
    }
}

pub fn size_to_size(size: &ir::types::ValSize) -> ptir::ValSize {
    match size {
        ir::types::ValSize::Size1 => ptir::ValSize::Size1,
        ir::types::ValSize::Size8 => ptir::ValSize::Size8,
        ir::types::ValSize::Size16 => ptir::ValSize::Size16,
        ir::types::ValSize::Size32 => ptir::ValSize::Size32,
        ir::types::ValSize::Size64 => ptir::ValSize::Size64,
        ir::types::ValSize::Size128 => ptir::ValSize::Size128,
        ir::types::ValSize::Size256 => ptir::ValSize::Size256,
        ir::types::ValSize::Size512 => ptir::ValSize::Size512,
    }
}

pub fn reg_to_reg(reg: ir::types::X86Regs, size: ir::types::ValSize) -> Option<Register> {
    match size {
        ir::types::ValSize::Size8 => match reg {
            ir::types::X86Regs::Rax => Some(Register::AL),
            ir::types::X86Regs::Rbx => Some(Register::BL),
            ir::types::X86Regs::Rcx => Some(Register::CL),
            ir::types::X86Regs::Rdx => Some(Register::DL),
            ir::types::X86Regs::Rsp => Some(Register::SPL),
            ir::types::X86Regs::Rbp => Some(Register::BPL),
            ir::types::X86Regs::Rsi => Some(Register::SIL),
            ir::types::X86Regs::Rdi => Some(Register::DIL),
            ir::types::X86Regs::R8 => Some(Register::R8L),
            ir::types::X86Regs::R9 => Some(Register::R9L),
            ir::types::X86Regs::R10 => Some(Register::R10L),
            ir::types::X86Regs::R11 => Some(Register::R11L),
            ir::types::X86Regs::R12 => Some(Register::R12L),
            ir::types::X86Regs::R13 => Some(Register::R13L),
            ir::types::X86Regs::R14 => Some(Register::R14L),
            ir::types::X86Regs::R15 => Some(Register::R15L),
            _ => None,
        },
        ir::types::ValSize::Size16 => match reg {
            ir::types::X86Regs::Rax => Some(Register::AX),
            ir::types::X86Regs::Rbx => Some(Register::BX),
            ir::types::X86Regs::Rcx => Some(Register::CX),
            ir::types::X86Regs::Rdx => Some(Register::DX),
            ir::types::X86Regs::Rsp => Some(Register::SP),
            ir::types::X86Regs::Rbp => Some(Register::BP),
            ir::types::X86Regs::Rsi => Some(Register::SI),
            ir::types::X86Regs::Rdi => Some(Register::DI),
            ir::types::X86Regs::R8 => Some(Register::R8W),
            ir::types::X86Regs::R9 => Some(Register::R9W),
            ir::types::X86Regs::R10 => Some(Register::R10W),
            ir::types::X86Regs::R11 => Some(Register::R11W),
            ir::types::X86Regs::R12 => Some(Register::R12W),
            ir::types::X86Regs::R13 => Some(Register::R13W),
            ir::types::X86Regs::R14 => Some(Register::R14W),
            ir::types::X86Regs::R15 => Some(Register::R15W),
            _ => None,
        },
        ir::types::ValSize::Size32 => match reg {
            ir::types::X86Regs::Rax => Some(Register::EAX),
            ir::types::X86Regs::Rbx => Some(Register::EBX),
            ir::types::X86Regs::Rcx => Some(Register::ECX),
            ir::types::X86Regs::Rdx => Some(Register::EDX),
            ir::types::X86Regs::Rsp => Some(Register::ESP),
            ir::types::X86Regs::Rbp => Some(Register::EBP),
            ir::types::X86Regs::Rsi => Some(Register::ESI),
            ir::types::X86Regs::Rdi => Some(Register::EDI),
            ir::types::X86Regs::R8 => Some(Register::R8D),
            ir::types::X86Regs::R9 => Some(Register::R9D),
            ir::types::X86Regs::R10 => Some(Register::R10D),
            ir::types::X86Regs::R11 => Some(Register::R11D),
            ir::types::X86Regs::R12 => Some(Register::R12D),
            ir::types::X86Regs::R13 => Some(Register::R13D),
            ir::types::X86Regs::R14 => Some(Register::R14D),
            ir::types::X86Regs::R15 => Some(Register::R15D),
            _ => None,
        },
        ir::types::ValSize::Size64 => match reg {
            ir::types::X86Regs::Rax => Some(Register::RAX),
            ir::types::X86Regs::Rbx => Some(Register::RBX),
            ir::types::X86Regs::Rcx => Some(Register::RCX),
            ir::types::X86Regs::Rdx => Some(Register::RDX),
            ir::types::X86Regs::Rsp => Some(Register::RSP),
            ir::types::X86Regs::Rbp => Some(Register::RBP),
            ir::types::X86Regs::Rsi => Some(Register::RSI),
            ir::types::X86Regs::Rdi => Some(Register::RDI),
            ir::types::X86Regs::R8 => Some(Register::R8),
            ir::types::X86Regs::R9 => Some(Register::R9),
            ir::types::X86Regs::R10 => Some(Register::R10),
            ir::types::X86Regs::R11 => Some(Register::R11),
            ir::types::X86Regs::R12 => Some(Register::R12),
            ir::types::X86Regs::R13 => Some(Register::R13),
            ir::types::X86Regs::R14 => Some(Register::R14),
            ir::types::X86Regs::R15 => Some(Register::R15),
            _ => None,
        },
        ir::types::ValSize::Size128 => match reg {
            ir::types::X86Regs::Zmm0 => Some(Register::XMM0),
            ir::types::X86Regs::Zmm1 => Some(Register::XMM1),
            ir::types::X86Regs::Zmm2 => Some(Register::XMM2),
            ir::types::X86Regs::Zmm3 => Some(Register::XMM3),
            ir::types::X86Regs::Zmm4 => Some(Register::XMM4),
            ir::types::X86Regs::Zmm5 => Some(Register::XMM5),
            ir::types::X86Regs::Zmm6 => Some(Register::XMM6),
            ir::types::X86Regs::Zmm7 => Some(Register::XMM7),
            ir::types::X86Regs::Zmm8 => Some(Register::XMM8),
            ir::types::X86Regs::Zmm9 => Some(Register::XMM9),
            ir::types::X86Regs::Zmm10 => Some(Register::XMM10),
            ir::types::X86Regs::Zmm11 => Some(Register::XMM11),
            ir::types::X86Regs::Zmm12 => Some(Register::XMM12),
            ir::types::X86Regs::Zmm13 => Some(Register::XMM13),
            ir::types::X86Regs::Zmm14 => Some(Register::XMM14),
            ir::types::X86Regs::Zmm15 => Some(Register::XMM15),
            _ => None,
        },
        ir::types::ValSize::Size256 => match reg {
            ir::types::X86Regs::Zmm0 => Some(Register::YMM0),
            ir::types::X86Regs::Zmm1 => Some(Register::YMM1),
            ir::types::X86Regs::Zmm2 => Some(Register::YMM2),
            ir::types::X86Regs::Zmm3 => Some(Register::YMM3),
            ir::types::X86Regs::Zmm4 => Some(Register::YMM4),
            ir::types::X86Regs::Zmm5 => Some(Register::YMM5),
            ir::types::X86Regs::Zmm6 => Some(Register::YMM6),
            ir::types::X86Regs::Zmm7 => Some(Register::YMM7),
            ir::types::X86Regs::Zmm8 => Some(Register::YMM8),
            ir::types::X86Regs::Zmm9 => Some(Register::YMM9),
            ir::types::X86Regs::Zmm10 => Some(Register::YMM10),
            ir::types::X86Regs::Zmm11 => Some(Register::YMM11),
            ir::types::X86Regs::Zmm12 => Some(Register::YMM12),
            ir::types::X86Regs::Zmm13 => Some(Register::YMM13),
            ir::types::X86Regs::Zmm14 => Some(Register::YMM14),
            ir::types::X86Regs::Zmm15 => Some(Register::YMM15),
            _ => None,
        },
        ir::types::ValSize::Size512 => match reg {
            ir::types::X86Regs::Zmm0 => Some(Register::ZMM0),
            ir::types::X86Regs::Zmm1 => Some(Register::ZMM1),
            ir::types::X86Regs::Zmm2 => Some(Register::ZMM2),
            ir::types::X86Regs::Zmm3 => Some(Register::ZMM3),
            ir::types::X86Regs::Zmm4 => Some(Register::ZMM4),
            ir::types::X86Regs::Zmm5 => Some(Register::ZMM5),
            ir::types::X86Regs::Zmm6 => Some(Register::ZMM6),
            ir::types::X86Regs::Zmm7 => Some(Register::ZMM7),
            ir::types::X86Regs::Zmm8 => Some(Register::ZMM8),
            ir::types::X86Regs::Zmm9 => Some(Register::ZMM9),
            ir::types::X86Regs::Zmm10 => Some(Register::ZMM10),
            ir::types::X86Regs::Zmm11 => Some(Register::ZMM11),
            ir::types::X86Regs::Zmm12 => Some(Register::ZMM12),
            ir::types::X86Regs::Zmm13 => Some(Register::ZMM13),
            ir::types::X86Regs::Zmm14 => Some(Register::ZMM14),
            ir::types::X86Regs::Zmm15 => Some(Register::ZMM15),
            _ => None,
        },
        _ => None,
    }
}

pub fn reg_to_flags(reg: ir::types::X86Regs) -> Flags {
    match reg {
        ir::types::X86Regs::Zf => Flags::ZF,
        ir::types::X86Regs::Sf => Flags::SF,
        ir::types::X86Regs::Of => Flags::OF,
        ir::types::X86Regs::Pf => Flags::PF,
        ir::types::X86Regs::Cf => Flags::CF,
        _ => panic!("Unsupported register"),
    }
}

pub fn write_proof_to_file(prf: Proof, addr: u64) -> () {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .append(true) // This is needed to append to file
        .open("log.prf")
        .unwrap();
    log::debug!("PROOF[0x{:x}: {}]", addr, prf.output_prf());
    file.write_all(format!("0x{:x}: {}\n", addr, prf.output_prf()).as_bytes())
        .expect("cannot write to file");
}

pub fn output_proof_hint(hint_str: String, rel: Option<ptir::Relationship>, addr: u64) -> () {
    let prf = Proof::Hint(hint_str, rel);
    write_proof_to_file(prf, addr);
}

pub trait AbstractAnalyzer<State: Lattice + VarState + Clone> {
    fn init_state(&self) -> State {
        Default::default()
    }
    fn process_branch(
        &self,
        _irmap: &IRMap,
        in_state: &State,
        succ_addrs: &Vec<u64>,
        _addr: &u64,
    ) -> Vec<(u64, State)> {
        succ_addrs
            .into_iter()
            .map(|addr| (addr.clone(), in_state.clone()))
            .collect()
    }
    fn aexec_unop(
        &self,
        in_state: &mut State,
        _opcode: &Unopcode,
        dst: &Value,
        _src: &Value,
        _loc_idx: &LocIdx,
    ) -> () {
        in_state.set_to_bot(dst)
    }
    fn aexec_binop(
        &self,
        in_state: &mut State,
        opcode: &Binopcode,
        dst: &Value,
        _src1: &Value,
        _src2: &Value,
        _loc_idx: &LocIdx,
    ) -> () {
        match opcode {
            Binopcode::Cmp => (),
            Binopcode::Test => (),
            _ => in_state.set_to_bot(dst),
        }
    }

    fn aexec(&self, in_state: &mut State, ir_instr: &Stmt, loc_idx: &LocIdx) -> () {
        match ir_instr {
            Stmt::Clear(dst, _srcs) => in_state.set_to_bot(dst),
            Stmt::Unop(opcode, dst, src) => self.aexec_unop(in_state, opcode, &dst, &src, loc_idx),
            Stmt::Binop(opcode, dst, src1, src2) => {
                self.aexec_binop(in_state, opcode, dst, src1, src2, loc_idx);
                match in_state.adjust_stack_offset(opcode, dst, src1, src2) {
                    Some(proof) => {
                        // log::info!("Proof[0x{:x}: {}]", loc_idx.addr, proof.output_prf());
                        // file.write_all(
                        //     format!("0x{:x}: {}\n", loc_idx.addr, proof.output_prf()).as_bytes(),
                        // )
                        // .expect("cannot write to file");
                    }
                    None => (),
                }
            }
            Stmt::Call(_) => in_state.on_call(),
            _ => (),
        }
    }

    fn analyze_block(&self, state: &State, irblock: &IRBlock) -> State {
        let mut new_state = state.clone();
        for (addr, instruction) in irblock.iter() {
            for (idx, ir_insn) in instruction.iter().enumerate() {
                log::trace!(
                    "Analyzing insn @ 0x{:x}: {:?}: state = {:?}",
                    addr,
                    ir_insn,
                    new_state
                );
                log::debug!("0x{:x}: {:?}", addr, ir_insn);
                self.aexec(
                    &mut new_state,
                    ir_insn,
                    &LocIdx {
                        addr: *addr,
                        idx: idx as u32,
                    },
                );
            }
        }
        new_state
    }
}

fn align_succ_addrs(addr: u64, succ_addrs: Vec<u64>) -> Vec<u64> {
    if succ_addrs.len() != 2 {
        return succ_addrs;
    }
    let a1 = succ_addrs[0];
    let a2 = succ_addrs[1];
    // TODO this may need further fix
    if a1 <= addr {
        return vec![a2, a1];
    }
    if a2 <= addr {
        return vec![a1, a2];
    }
    if a1 < a2 {
        return vec![a1, a2];
    }
    if a1 >= a2 {
        return vec![a2, a1];
    }
    panic!("Unreachable");
}

pub fn run_worklist<T: AbstractAnalyzer<State>, State: VarState + Lattice + Clone>(
    cfg: &VW_CFG,
    irmap: &IRMap,
    analyzer: &T,
) -> AnalysisResult<State> {
    let mut statemap: HashMap<u64, State> = HashMap::new();
    let mut worklist: VecDeque<u64> = VecDeque::new();
    worklist.push_back(cfg.entrypoint);
    statemap.insert(cfg.entrypoint, analyzer.init_state());

    while !worklist.is_empty() {
        let addr = worklist.pop_front().unwrap();
        let irblock = irmap.get(&addr).unwrap();
        let state = statemap.get(&addr).unwrap();
        let new_state = analyzer.analyze_block(state, irblock);
        let succ_addrs_unaligned: Vec<u64> = cfg.graph.neighbors(addr).collect();
        let succ_addrs: Vec<u64> = align_succ_addrs(addr, succ_addrs_unaligned);
        log::debug!("Processing Block: 0x{:x} -> {:x?}", addr, succ_addrs);
        for (succ_addr, branch_state) in
            analyzer.process_branch(irmap, &new_state, &succ_addrs, &addr)
        {
            let has_change = if statemap.contains_key(&succ_addr) {
                let old_state = statemap.get(&succ_addr).unwrap();
                let merged_state = old_state.meet(&branch_state, &LocIdx { addr: addr, idx: 0 });

                if merged_state > *old_state {
                    log::debug!("{:?} {:?}", merged_state, old_state);
                    panic!("Meet monoticity error");
                }
                let has_change = *old_state != merged_state;
                log::debug!(
                    "At block 0x{:x}: merged input {:?}",
                    succ_addr,
                    merged_state
                );
                statemap.insert(succ_addr, merged_state);
                has_change
            } else {
                log::debug!("At block 0x{:x}: new input {:?}", succ_addr, branch_state);
                statemap.insert(succ_addr, branch_state);
                true
            };

            if has_change && !worklist.contains(&succ_addr) {
                worklist.push_back(succ_addr);
            }
        }
    }
    statemap
}
