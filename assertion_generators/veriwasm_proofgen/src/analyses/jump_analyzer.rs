use crate::analyses::*;
use crate::{analyses, ir, lattices, loaders};
use analyses::reaching_defs::ReachingDefnAnalyzer;
use analyses::{AbstractAnalyzer, AnalysisResult};
use core::panic;
use ir::types::{Binopcode, IRMap, MemArg, MemArgs, Unopcode, ValSize, Value, X86Regs};
use ir::utils::{get_rsp_offset, is_frame_access, is_stack_access};
use lattices::reachingdefslattice::{LocIdx, ReachLattice};
use lattices::switchlattice::{SwitchLattice, SwitchValue, SwitchValueLattice};
use lattices::{VarSlot, VarState};
use loaders::types::VwMetadata;
use log::debug;
use ptir::*;
use std::convert::TryFrom;
use std::default::Default;
use yaxpeax_x86::long_mode::Opcode;

use SwitchValue::{JmpOffset, JmpTarget, SwitchBase, UpperBound};
use ValSize::*;
use X86Regs::*;

pub struct SwitchAnalyzer {
    pub metadata: VwMetadata,
    pub reaching_defs: AnalysisResult<ReachLattice>,
    pub reaching_analyzer: ReachingDefnAnalyzer,
}

impl AbstractAnalyzer<SwitchLattice> for SwitchAnalyzer {
    fn aexec_unop(
        &self,
        in_state: &mut SwitchLattice,
        opcode: &Unopcode,
        dst: &Value,
        src: &Value,
        loc_idx: &LocIdx,
    ) -> () {
        let aeval = self.aeval_unop(in_state, src);
        // log::debug!(
        //     "Jump analyzer: unop at {:x}: {:?} {:?} {:?} ({:x?})",
        //     loc_idx.addr,
        //     opcode,
        //     dst,
        //     src,
        //     aeval
        // );
        in_state.set(dst, aeval.clone());
        let (left, dst_size) = match dst {
            Value::Mem(size, args) => {
                let is_stack = is_stack_access(dst)
                    || is_stack_access(src)
                    || is_frame_access(dst)
                    || is_frame_access(src);
                if !is_stack {
                    return;
                }
                let mut mem = args_to_var(args);
                mem.size = size_to_size(size);
                (LocationBuilder::new().memcell(mem).build(), size)
            }
            Value::Reg(reg, size) => (
                unalias_location(
                    LocationBuilder::new()
                        .register(reg_to_reg(*reg, *size).unwrap())
                        .build(),
                )
                .unwrap(),
                size,
            ),
            _ => panic!("LHS must not be an immediate or RIPConst"),
        };
        let right = match aeval.v {
            Some(SwitchBase(imm)) => {
                debug!(
                    "SwitchBase: unop at 0x{:x}: {:?} ({:x?})",
                    loc_idx.addr, src, imm
                );
                match src {
                    Value::Reg(reg, size) => GenericExpr::Var(
                        LocationBuilder::new()
                            .register(reg_to_reg(*reg, *size).unwrap())
                            .build(),
                    ),
                    // Let's simply return because these cases are handled
                    // somewhere else. And here, the size/sort of imm is very
                    // unreliable.
                    _ => return,
                    // Value::Imm(_, _, _) => GenericExpr::Imm(Imm {
                    //     value: imm as u64,
                    //     size: size_to_size(dst_size),
                    // }),
                    // Value::Mem(_, _) => return, //panic!("Unseen case at {:x}: {:?}", loc_idx.addr, src),
                    // Value::RIPConst => return,
                }
            }
            Some(UpperBound(imm)) => {
                if imm == 1 {
                    // not handling this case
                    return;
                }
                debug!(
                    "UpperBound: unop at 0x{:x}: {:?} ({:x?})",
                    loc_idx.addr, src, imm
                );
                match src {
                    Value::Reg(reg, size) => GenericExpr::Var(
                        LocationBuilder::new()
                            .register(reg_to_reg(*reg, *size).unwrap())
                            .build(),
                    ),
                    // Let's simply return because these cases are handled
                    // somewhere else. And here, the size/sort of imm is very
                    // unreliable.
                    _ => return,
                    // Value::Imm(_, _, _) => GenericExpr::Imm(Imm {
                    //     value: imm as u64,
                    //     size: size_to_size(dst_size),
                    // }),
                    // Value::Mem(_, _) => return, //panic!("Unseen case at {:x}: {:?}", loc_idx.addr, src),
                    // Value::RIPConst => return,
                }
            }
            Some(JmpOffset(base, bound)) => {
                debug!(
                    "JmpOffset: unop at 0x{:x}: {:?} ({:x?})",
                    loc_idx.addr, src, aeval.v
                );
                // let base = GenericExpr::Imm(Imm::from(base));
                // let bound = GenericExpr::Imm(Imm::from(bound));
                let rel = rel!(
                    Expr::Var(left),
                    bv!("="),
                    Expr::Const(Const::new(
                        Sort::BitVec(64),
                        format!("JmpOffset_{:x}", base)
                    ))
                );
                output_proof_hint("JmpPtrCalc".to_string(), Some(rel), loc_idx.addr);
                // TODO this is also a potential early return place
                match src {
                    Value::Mem(size, memarg) => GenericExpr::Var(
                        LocationBuilder::new().memcell(args_to_var(memarg)).build(),
                    ),
                    _ => panic!("Never expect to reach here {:x}: {:?}", loc_idx.addr, src),
                }
            }
            None => {
                debug!(
                    "Jump analyzer: unop at 0x{:x}: {:?} ({:x?})",
                    loc_idx.addr, src, aeval.v
                );
                return;
            }
            c => {
                // JmpTarget not handled yet, may need to handle it in the future
                panic!(
                    "Jump analyzer: unop at 0x{:x}: {:?} ({:x?})",
                    loc_idx.addr, src, c
                );
                // return;
            }
        };
        let proof: Proof = Proof::Asgn(Assignment::new(left, right));
        write_proof_to_file(proof, loc_idx.addr);
    }

    fn aexec_binop(
        &self,
        in_state: &mut SwitchLattice,
        opcode: &Binopcode,
        dst: &Value,
        src1: &Value,
        src2: &Value,
        loc_idx: &LocIdx,
    ) -> () {
        if let Binopcode::Cmp = opcode {
            match (src1, src2) {
                (Value::Reg(regnum, _), Value::Imm(_, _, imm))
                | (Value::Imm(_, _, imm), Value::Reg(regnum, _)) => {
                    let reg_def = self
                        .reaching_analyzer
                        .fetch_def(&self.reaching_defs, loc_idx);
                    let src_loc = reg_def.regs.get_reg(*regnum, Size64);
                    in_state.regs.set_reg(
                        Zf,
                        Size64,
                        SwitchValueLattice::new(SwitchValue::ZF(*imm as u32, *regnum, src_loc)),
                    );
                    let cmp_rel = if let (Value::Reg(regnum, size), Value::Imm(_, _, imm)) =
                        (src1, src2)
                    {
                        expr!(
                            Expr::from(
                                LocationBuilder::new()
                                    .register(reg_to_reg(*regnum, *size).unwrap())
                                    .build()
                            ),
                            bv!("bvult"),
                            Expr::from(Imm::from(*imm as u32))
                        )
                    } else if let (Value::Imm(_, _, imm), Value::Reg(regnum, size)) = (src1, src2) {
                        expr!(
                            Expr::from(Imm::from(*imm as u32)),
                            bv!("bvult"),
                            Expr::from(
                                LocationBuilder::new()
                                    .register(reg_to_reg(*regnum, *size).unwrap())
                                    .build()
                            )
                        )
                    } else {
                        panic!("Unreachable")
                    };
                    let assignment =
                        Proof::Asgn(Assignment::new(Location::Flag(Flags::CF), cmp_rel));
                    write_proof_to_file(assignment, loc_idx.addr);
                }
                _ => (),
            }
        }

        match opcode {
            Binopcode::Cmp => (),
            Binopcode::Test => {
                // TODO handle test in semantics?
                in_state.regs.set_reg(Zf, Size64, Default::default());
            }
            _ => {
                let aeval = self.aeval_binop(in_state, opcode, src1, src2);
                in_state.set(dst, aeval.clone());
                if let Some(JmpTarget(base, offset)) = aeval.v {
                    debug!(
                        "JmpTarget: binop at 0x{:x}: {:?}, {:?} ({:x?})",
                        loc_idx.addr, src1, src2, aeval.v
                    );
                    let left = match dst {
                        Value::Mem(size, args) => {
                            panic!("Unseen JmpTarget mem case at {:x}", loc_idx.addr)
                        }
                        Value::Reg(reg, size) => LocationBuilder::new()
                            .register(reg_to_reg(*reg, Size64).unwrap())
                            .build(),
                        _ => panic!("shouldn't reach here"),
                    };
                    let rel = rel!(
                        Expr::Var(left),
                        bv!("="),
                        Expr::Const(Const::new(
                            Sort::BitVec(64),
                            format!("JmpTarget_{:x}", base),
                        ))
                    );
                    output_proof_hint("JmpPtrCalc".to_string(), Some(rel), loc_idx.addr);

                    if let (Value::Reg(reg1, size1), Value::Reg(reg2, size2)) = (src1, src2) {
                        let assignment = Proof::Asgn(Assignment {
                            lhs: left,
                            rhs: GenericExpr::Binary(
                                bv!("bvadd"),
                                Box::new(GenericExpr::Var(
                                    LocationBuilder::new()
                                        .register(reg_to_reg(*reg1, *size1).unwrap())
                                        .build(),
                                )),
                                Box::new(GenericExpr::Var(
                                    LocationBuilder::new()
                                        .register(reg_to_reg(*reg2, *size2).unwrap())
                                        .build(),
                                )),
                            ),
                        });
                        write_proof_to_file(assignment, loc_idx.addr);
                    }
                }
            }
        }
    }

    fn process_branch(
        &self,
        irmap: &IRMap,
        in_state: &SwitchLattice,
        succ_addrs: &Vec<u64>,
        addr: &u64,
    ) -> Vec<(u64, SwitchLattice)> {
        if succ_addrs.len() == 2 {
            let mut not_branch_state = in_state.clone();
            let mut branch_state = in_state.clone();
            if let Some(SwitchValue::ZF(bound, regnum, checked_defs)) =
                &in_state.regs.get_reg(Zf, Size64).v
            {
                not_branch_state.regs.set_reg(
                    *regnum,
                    Size64,
                    SwitchValueLattice {
                        v: Some(UpperBound(*bound)),
                    },
                );
                let instr = irmap
                    .get(addr)
                    .unwrap()
                    .into_iter()
                    .next_back()
                    .unwrap()
                    .1
                    .clone();
                match instr.into_iter().next().unwrap() {
                    Stmt::Branch(op, _) => match op {
                        Opcode::JNB
                        | Opcode::JB
                        | Opcode::JNZ
                        | Opcode::JZ
                        | Opcode::JNA
                        | Opcode::JA => {
                            let rel = rel!(
                                Expr::Var(GenericLocation::Register(
                                    reg_to_reg(*regnum, Size32).unwrap()
                                )),
                                bv!("="),
                                Expr::Const(Const::new(
                                    Sort::BitVec(64),
                                    format!("JmpIdx_{:x}", *bound)
                                ))
                            );
                            output_proof_hint("JmpPtrCalc".to_string(), Some(rel), succ_addrs[0]);
                        }
                        _ => (),
                    },
                    _ => (),
                }

                let defs_state = self.reaching_defs.get(addr).unwrap();
                let ir_block = irmap.get(addr).unwrap();
                let defs_state = self.reaching_analyzer.analyze_block(defs_state, ir_block);
                //propagate bound across registers with the same reaching def
                for idx in X86Regs::iter() {
                    if idx != *regnum {
                        let reg_def = defs_state.regs.get_reg(idx, Size64);
                        if (!reg_def.is_empty()) && (&reg_def == checked_defs) {
                            not_branch_state.regs.set_reg(
                                idx,
                                Size64,
                                SwitchValueLattice {
                                    v: Some(UpperBound(*bound)),
                                },
                            );
                        }
                    }
                }
                //propagate bound across stack slots with the same upper bound
                for (stack_offset, stack_slot) in defs_state.stack.map.iter() {
                    if !checked_defs.is_empty() && (&stack_slot.value == checked_defs) {
                        let v = SwitchValueLattice {
                            v: Some(UpperBound(*bound)),
                        };
                        let vv = VarSlot {
                            size: stack_slot.size,
                            value: v,
                        };
                        not_branch_state.stack.map.insert(*stack_offset, vv);
                    }
                }
            }
            branch_state.regs.set_reg(Zf, Size64, Default::default());
            not_branch_state
                .regs
                .set_reg(Zf, Size64, Default::default());
            vec![
                (succ_addrs[0].clone(), not_branch_state),
                (succ_addrs[1].clone(), branch_state),
            ]
        } else {
            succ_addrs
                .into_iter()
                .map(|addr| (addr.clone(), in_state.clone()))
                .collect()
        }
    }
}

impl SwitchAnalyzer {
    fn aeval_unop_mem(
        &self,
        in_state: &SwitchLattice,
        memargs: &MemArgs,
        memsize: &ValSize,
    ) -> SwitchValueLattice {
        if let Some(offset) = get_rsp_offset(memargs) {
            return in_state.stack.get(offset, memsize.into_bytes());
        }
        if let MemArgs::MemScale(
            MemArg::Reg(regnum1, size1),
            MemArg::Reg(regnum2, size2),
            MemArg::Imm(_, _, immval),
        ) = memargs
        {
            if let (Some(SwitchBase(base)), Some(UpperBound(bound)), 4) = (
                in_state.regs.get_reg(*regnum1, *size1).v,
                in_state.regs.get_reg(*regnum2, *size2).v,
                immval,
            ) {
                return SwitchValueLattice::new(JmpOffset(base, bound));
            }
        }
        Default::default()
    }

    // 1. if unop is a constant, set as constant -- done
    // 2. if reg, return reg -- done
    // 3. if stack access, return stack access -- done
    // 4. x = mem[switch_base + offset * 4]
    pub fn aeval_unop(&self, in_state: &SwitchLattice, src: &Value) -> SwitchValueLattice {
        match src {
            Value::Mem(memsize, memargs) => self.aeval_unop_mem(in_state, memargs, memsize),
            Value::Reg(regnum, size) => in_state.regs.get_reg(*regnum, *size),
            Value::Imm(_, _, immval) => {
                if *immval == 0 {
                    SwitchValueLattice::new(UpperBound(1))
                } else {
                    SwitchValueLattice::new(SwitchBase(*immval as u32))
                }
            }
            Value::RIPConst => Default::default(),
        }
    }

    // 1. x = switch_base + offset
    pub fn aeval_binop(
        &self,
        in_state: &SwitchLattice,
        opcode: &Binopcode,
        src1: &Value,
        src2: &Value,
    ) -> SwitchValueLattice {
        if let Binopcode::Add = opcode {
            if let (Value::Reg(regnum1, size1), Value::Reg(regnum2, size2)) = (src1, src2) {
                match (
                    in_state.regs.get_reg(*regnum1, *size1).v,
                    in_state.regs.get_reg(*regnum2, *size2).v,
                ) {
                    (Some(SwitchBase(base)), Some(JmpOffset(_, offset)))
                    | (Some(JmpOffset(_, offset)), Some(SwitchBase(base))) => {
                        return SwitchValueLattice::new(JmpTarget(base, offset))
                    }
                    _ => return Default::default(),
                };
            }
        }
        Default::default()
    }
}
