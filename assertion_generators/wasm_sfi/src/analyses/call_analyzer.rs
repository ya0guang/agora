use crate::analyses::*;
use crate::ir::utils::is_frame_access;
use crate::{analyses, ir, lattices, loaders};
use analyses::reaching_defs::ReachingDefnAnalyzer;
use analyses::{AbstractAnalyzer, AnalysisResult};
use ir::types::{
    Binopcode, IRBlock, IRMap, MemArg, MemArgs, Stmt, Unopcode, ValSize, Value, X86Regs,
};
use ir::utils::{extract_stack_offset, is_stack_access};
use lattices::calllattice::{CallCheckLattice, CallCheckValue, CallCheckValueLattice};
use lattices::davlattice::DAV;
use lattices::reachingdefslattice::{LocIdx, ReachLattice};
use lattices::{VarSlot, VarState};
use loaders::types::VwMetadata;
use ptir::*;
use std::convert::TryFrom;
use std::default::Default;
use std::fs;
use yaxpeax_core::analyses::control_flow::VW_CFG;
use yaxpeax_x86::long_mode::Opcode;

use CallCheckValue::*;
use ValSize::*;
use X86Regs::*;

pub struct CallAnalyzer {
    pub metadata: VwMetadata,
    pub reaching_defs: AnalysisResult<ReachLattice>,
    pub reaching_analyzer: ReachingDefnAnalyzer,
    pub funcs: Vec<u64>,
    pub irmap: IRMap,
    pub cfg: VW_CFG,
}

impl CallAnalyzer {
    //1. get enclosing block addr
    //2. get result for that block start
    //3. get result for specific addr
    pub fn fetch_result(
        &self,
        result: &AnalysisResult<CallCheckLattice>,
        loc_idx: &LocIdx,
    ) -> CallCheckLattice {
        let a = 5u64;
        if self.cfg.blocks.contains_key(&loc_idx.addr) {
            return result.get(&loc_idx.addr).unwrap().clone();
        }
        let block_addr = self.cfg.prev_block(loc_idx.addr).unwrap().start;
        let irblock = self.irmap.get(&block_addr).unwrap();
        let mut a_state = result.get(&block_addr).unwrap().clone();
        for (addr, instruction) in irblock.iter() {
            for (idx, ir_insn) in instruction.iter().enumerate() {
                if &loc_idx.addr == addr && (loc_idx.idx as usize) == idx {
                    return a_state;
                }
                self.aexec(
                    &mut a_state,
                    ir_insn,
                    &LocIdx {
                        addr: *addr,
                        idx: idx as u32,
                    },
                );
            }
        }
        unimplemented!()
    }

    pub fn get_fn_ptr_type(
        &self,
        result: &AnalysisResult<CallCheckLattice>,
        loc_idx: &LocIdx,
        src: &Value,
    ) -> Option<u32> {
        let def_state = self.fetch_result(result, loc_idx);
        if let Value::Reg(regnum, size) = src {
            let aval = def_state.regs.get_reg(*regnum, *size);
            if let Some(FnPtr(ty)) = aval.v {
                return Some(ty);
            }
        }
        None
    }
}

impl AbstractAnalyzer<CallCheckLattice> for CallAnalyzer {
    fn analyze_block(&self, state: &CallCheckLattice, irblock: &IRBlock) -> CallCheckLattice {
        let mut new_state = state.clone();
        for (addr, instruction) in irblock.iter() {
            for (idx, ir_insn) in instruction.iter().enumerate() {
                self.aexec(
                    &mut new_state,
                    ir_insn,
                    &LocIdx {
                        addr: *addr,
                        idx: idx as u32,
                    },
                );
                log::debug!(
                    "Call analyzer: stmt at 0x{:x}: {:?} with state {:x?}",
                    addr,
                    ir_insn,
                    new_state
                );
            }
        }
        new_state
    }

    fn aexec_unop(
        &self,
        in_state: &mut CallCheckLattice,
        opcode: &Unopcode,
        dst: &Value,
        src: &Value,
        loc_idx: &LocIdx,
    ) -> () {
        let aeval = self.aeval_unop(in_state, src);
        log::debug!(
            "Call analyzer: unop at {:x}: {:?} {:?} {:?} ({:x?})",
            loc_idx.addr,
            opcode,
            dst,
            src,
            aeval
        );
        in_state.set(dst, aeval.clone());
        let dst_size;
        let left: Location = match dst {
            Value::Mem(size, args) => {
                // TODO: maybe check the access type, should only ignore heap
                // accesses. However, doesn't seem to be a problem for now, as
                // other passes generates proofs + hints for other accesses.
                let is_stack = is_stack_access(dst)
                    || is_stack_access(src)
                    || is_frame_access(dst)
                    || is_frame_access(src);
                if !is_stack {
                    return;
                }
                let mut mem = args_to_var(args);
                mem.size = size_to_size(size);
                dst_size = size;
                LocationBuilder::new().memcell(mem).build()
                // return;
            }
            Value::Reg(reg, size) => {
                dst_size = size;
                // TODO: The size here is incoherent with the size limitation
                // in proof validator, needs rework.
                unalias_location(
                    LocationBuilder::new()
                        .register(reg_to_reg(*reg, *size).unwrap())
                        .build(),
                )
                .unwrap()
            }
            _ => panic!("LHS must not be an immediate or RIPConst"),
        };
        let right: Expr = match aeval.v {
            Some(LucetTablesBase) => {
                let rel = Relationship {
                    relationship: bv!("="),
                    lhs: Expr::Var(left),
                    rhs: Expr::Const(Const::new(Sort::BitVec(64), "LucetTablesBase".to_string())),
                };
                output_proof_hint("FuncPtrCalc".to_string(), Some(rel), loc_idx.addr);
                return;
            }
            Some(TableSize) => {
                let rel = Relationship {
                    relationship: bv!("="),
                    lhs: Expr::Var(left),
                    rhs: Expr::Const(Const::new(Sort::BitVec(64), "TableSize".to_string())),
                };
                output_proof_hint("FuncPtrCalc".to_string(), Some(rel), loc_idx.addr);
                return;
            }
            Some(GuestTableBase) => {
                let rel = Relationship {
                    relationship: bv!("="),
                    lhs: Expr::Var(left),
                    rhs: Expr::Const(Const::new(Sort::BitVec(64), "GuestTableBase".to_string())),
                };
                output_proof_hint("FuncPtrCalc".to_string(), Some(rel), loc_idx.addr);
                return;
            }
            Some(TypeOf(r)) => {
                let rel = rel!(
                    Expr::Var(left),
                    bv!("="),
                    Expr::Const(Const::new(
                        Sort::BitVec(64),
                        format!("FnType_0x{:x}", loc_idx.addr)
                    ))
                );
                output_proof_hint("FuncPtrCalc".to_string(), Some(rel), loc_idx.addr);
                return;
            }
            Some(FnPtr(dummy)) => {
                let rel = Relationship {
                    relationship: bv!("="),
                    lhs: Expr::Var(left),
                    rhs: Expr::Const(Const::new(Sort::BitVec(64), "FnPtr".to_string())),
                };
                match dummy {
                    0xFFFF => output_proof_hint("RIPConst".to_string(), Some(rel), loc_idx.addr),
                    // TODO handle type index
                    0x7777 => output_proof_hint("FuncPtrCalc".to_string(), Some(rel), loc_idx.addr),
                    d if d < 0x10 => {
                        output_proof_hint("FuncPtrCalc".to_string(), Some(rel), loc_idx.addr)
                    }
                    _ => panic!("Unseen case {}", dummy),
                }
                return;
            }
            Some(Constant(val)) => {
                log::debug!("Constant: {:?}", src);
                match opcode {
                    Unopcode::Movsx => return,
                    _ => (),
                }
                let imm = Expr::Imm(Imm {
                    value: val,
                    size: size_to_size(dst_size),
                });
                match src {
                    Value::Reg(reg, size) => GenericExpr::Var(
                        LocationBuilder::new()
                            .register(reg_to_reg(*reg, *size).unwrap())
                            .build(),
                    ),
                    Value::Imm(_, _, _) => imm, // May need to handle this case
                    _ => return, // panic!("Unseen case at {:x}: {:?}", loc_idx.addr, src),
                }
            }
            Some(PtrOffset(_)) | Some(CheckedVal) => match src {
                Value::Reg(reg, size) => GenericExpr::Var(
                    LocationBuilder::new()
                        .register(reg_to_reg(*reg, *size).unwrap())
                        .build(),
                ),
                _ => return,
            },
            None => return,
            c => panic!("Unop: Unseen case {:?}", c),
        };
        let proof: Proof = Proof::Asgn(Assignment::new(left, right));
        write_proof_to_file(proof, loc_idx.addr);
    }

    fn aexec_binop(
        &self,
        in_state: &mut CallCheckLattice,
        opcode: &Binopcode,
        dst: &Value,
        src1: &Value,
        src2: &Value,
        loc_idx: &LocIdx,
    ) -> () {
        match (opcode, src1, src2) {
            (Binopcode::Cmp, Value::Reg(regnum1, size1), Value::Reg(regnum2, size2)) => {
                if let Some(TableSize) = in_state.regs.get_reg(*regnum2, *size2).v {
                    in_state.regs.set_reg(
                        Zf,
                        Size64,
                        CallCheckValueLattice::new(CheckFlag(0, *regnum1)),
                    );
                    let cmp_rel = expr!(
                        Expr::from(
                            LocationBuilder::new()
                                .register(reg_to_reg(*regnum1, *size1).unwrap())
                                .build()
                        ),
                        bv!("bvult"),
                        Expr::from(
                            LocationBuilder::new()
                                .register(reg_to_reg(*regnum2, *size2).unwrap())
                                .build()
                        )
                    );
                    let assignment =
                        Proof::Asgn(Assignment::new(Location::Flag(Flags::CF), cmp_rel));
                    write_proof_to_file(assignment, loc_idx.addr);
                }
                if let Some(TableSize) = in_state.regs.get_reg(*regnum1, *size1).v {
                    in_state.regs.set_reg(
                        Zf,
                        Size64,
                        CallCheckValueLattice::new(CheckFlag(0, *regnum2)),
                    );
                    let cmp_rel = expr!(
                        Expr::from(
                            LocationBuilder::new()
                                .register(reg_to_reg(*regnum1, *size1).unwrap())
                                .build()
                        ),
                        bv!("bvult"),
                        Expr::from(
                            LocationBuilder::new()
                                .register(reg_to_reg(*regnum2, *size2).unwrap())
                                .build()
                        )
                    );
                    let assignment =
                        Proof::Asgn(Assignment::new(Location::Flag(Flags::CF), cmp_rel));
                    write_proof_to_file(assignment, loc_idx.addr);
                }

                if let Some(TypeOf(r)) = in_state.regs.get_reg(*regnum1, *size1).v {
                    if let Some(Constant(c)) = in_state.regs.get_reg(*regnum2, *size2).v {
                        in_state.regs.set_reg(
                            Zf,
                            Size64,
                            CallCheckValueLattice::new(TypeCheckFlag(r, c as u32)),
                        );
                        let cmp_rel = expr!(
                            Expr::from(
                                LocationBuilder::new()
                                    .register(reg_to_reg(*regnum1, *size1).unwrap())
                                    .build()
                            ),
                            bv!("="),
                            // Expr::from(Imm::from(c as u64))
                            // Can't go directly with Imm, because it won't pass
                            // validation. Using the register instead.
                            Expr::from(
                                LocationBuilder::new()
                                    .register(reg_to_reg(*regnum2, *size2).unwrap())
                                    .build()
                            )
                        );
                        let assignment =
                            Proof::Asgn(Assignment::new(Location::Flag(Flags::ZF), cmp_rel));
                        write_proof_to_file(assignment, loc_idx.addr);
                    }
                }
            }
            (Binopcode::Cmp, Value::Reg(regnum, size), Value::Imm(_, _, c)) => {
                if let Some(TypeOf(r)) = in_state.regs.get_reg(*regnum, *size).v {
                    log::debug!(
                        "{:x}: Settng zf = TypeCheckFlag({:?}, {:?}) from {:?}",
                        loc_idx.addr,
                        X86Regs::try_from(r).unwrap(),
                        c,
                        X86Regs::try_from(*regnum).unwrap()
                    );
                    in_state.regs.set_reg(
                        Zf,
                        Size64,
                        CallCheckValueLattice::new(TypeCheckFlag(r, *c as u32)),
                    );
                    let cmp_rel = expr!(
                        Expr::from(
                            LocationBuilder::new()
                                .register(reg_to_reg(*regnum, *size).unwrap())
                                .build()
                        ),
                        bv!("="),
                        Expr::from(Imm::from(*c as i64))
                    );
                    let assignment =
                        Proof::Asgn(Assignment::new(Location::Flag(Flags::ZF), cmp_rel));
                    write_proof_to_file(assignment, loc_idx.addr);
                }
            }
            (Binopcode::Test, _, _) => (),
            _ => {
                let aval = self.aeval_binop(in_state, opcode, src1, src2, loc_idx);
                if let (Value::Reg(regnum1, size1), Value::Imm(_, _, 4)) = (src1, src2) {
                    if let Binopcode::Shl = opcode {
                        let assign = Proof::Asgn(Assignment {
                            lhs: LocationBuilder::new()
                                .register(reg_to_reg(*regnum1, Size64).unwrap())
                                .build(),
                            rhs: expr!(
                                Expr::Var(
                                    LocationBuilder::new()
                                        .register(reg_to_reg(*regnum1, *size1).unwrap())
                                        .build()
                                ),
                                bv!("bvshl"),
                                Expr::from(Imm::from(4 as u8))
                            ),
                        });
                        write_proof_to_file(assign, loc_idx.addr);
                    }
                }
                in_state.set(dst, aval.clone());
                let left_hand_side = match dst {
                    Value::Mem(size, args) => return,
                    Value::Reg(reg, size) => LocationBuilder::new()
                        .register(reg_to_reg(*reg, Size64).unwrap())
                        .build(),
                    _ => panic!("shouldn't reach here"),
                };
                let right_hand_side = match aval.v {
                    Some(PtrOffset(offset)) => match offset {
                        DAV::Checked => {
                            let rel = Relationship {
                                relationship: bv!("="),
                                lhs: Expr::Var(left_hand_side),
                                rhs: Expr::Const(Const::new(
                                    Sort::BitVec(64),
                                    "TableOffset".to_string(),
                                )),
                            };
                            output_proof_hint("FuncPtrCalc".to_string(), Some(rel), loc_idx.addr);
                        }
                        // These two cases will appear in the future.
                        DAV::Unchecked(_) => {
                            let rel = Relationship {
                                relationship: bv!("="),
                                lhs: Expr::Var(left_hand_side),
                                rhs: Expr::Const(Const::new(
                                    Sort::BitVec(64),
                                    "UncheckedTableOffset".to_string(),
                                )),
                            };
                            output_proof_hint("FuncPtrCalc".to_string(), Some(rel), loc_idx.addr);
                            //panic!("Unchecked ptr offset at 0x{:x}", loc_idx.addr),
                        }
                        DAV::Unknown => todo!(),
                    },
                    None => return,
                    _ => panic!("Binop: Unseen case"),
                };
            }
        }
    }

    fn process_branch(
        &self,
        irmap: &IRMap,
        in_state: &CallCheckLattice,
        succ_addrs: &Vec<u64>,
        addr: &u64,
    ) -> Vec<(u64, CallCheckLattice)> {
        log::info!("Processing branch: 0x{:x}", addr);
        if succ_addrs.len() == 2 {
            let last_inst = irmap
                .get(addr)
                .expect("no inst@addr")
                .last()
                .expect("no inst@block");
            let br_stmt = last_inst.1.last().expect("no IR for last instruction");
            let &br_addr = &last_inst.0;
            let br_opcode = match br_stmt {
                Stmt::Branch(op, _) => Some(op),
                _ => None,
            };

            let (is_unsigned_cmp, is_je, flip) = match br_opcode {
                Some(Opcode::JB) => (true, false, false),
                Some(Opcode::JNB) => {
                    let assignment = Proof::Asgn(Assignment {
                        lhs: LocationBuilder::new().register(Register::RIP).build(),
                        rhs: Expr::Ite(
                            Box::new(Expr::Var(Location::Flag(Flags::CF))),
                            Box::new(Expr::Imm(Imm::from(succ_addrs[0]))),
                            Box::new(Expr::Imm(Imm::from(succ_addrs[1]))),
                        ),
                    });
                    write_proof_to_file(assignment, br_addr);
                    (true, false, true)
                }
                Some(Opcode::JZ) => (false, true, false),
                Some(Opcode::JNZ) => {
                    let assignment = Proof::Asgn(Assignment {
                        lhs: LocationBuilder::new().register(Register::RIP).build(),
                        rhs: Expr::Ite(
                            Box::new(Expr::Var(Location::Flag(Flags::ZF))),
                            Box::new(Expr::Imm(Imm::from(succ_addrs[0]))),
                            Box::new(Expr::Imm(Imm::from(succ_addrs[1]))),
                        ),
                    });
                    write_proof_to_file(assignment, br_addr);
                    (false, true, true)
                }
                _ => (false, false, false),
            };

            log::debug!(
                "{:x}: is_unsigned_cmp {} is_je {} flip {}",
                addr,
                is_unsigned_cmp,
                is_je,
                flip
            );

            let mut not_branch_state = in_state.clone();
            let mut branch_state = in_state.clone();

            let not_branch_prfs = Vec::new();
            let mut branch_prfs = Vec::new();

            if is_unsigned_cmp {
                if let Some(CheckFlag(_, regnum)) = not_branch_state.regs.get_reg(Zf, Size64).v {
                    log::debug!("branch at 0x{:x}: CheckFlag for reg {:?}", addr, regnum);
                    let new_val = CallCheckValueLattice {
                        v: Some(CheckedVal),
                    };
                    branch_state.regs.set_reg(regnum, Size64, new_val.clone());
                    let mut rel = Relationship {
                        relationship: bv!("="),
                        lhs: Expr::Var(GenericLocation::Register(
                            reg_to_reg(regnum, Size64).unwrap(),
                        )),
                        rhs: Expr::Const(Const::new(Sort::BitVec(64), "TableIdx".to_string())),
                    };
                    branch_prfs.push(Proof::Hint("FuncPtrCalc".to_string(), Some(rel.clone())));

                    //1. propagate checked values in registers
                    let defs_state = self.reaching_defs.get(addr).unwrap();
                    let ir_block = irmap.get(addr).unwrap();
                    let defs_state = self.reaching_analyzer.analyze_block(defs_state, ir_block);
                    let checked_defs = defs_state.regs.get_reg(regnum, Size64);
                    for idx in X86Regs::iter() {
                        let reg_def = defs_state.regs.get_reg(idx, Size64);
                        if (!reg_def.is_empty()) && (reg_def == checked_defs) {
                            branch_state.regs.set_reg(idx, Size64, new_val.clone());
                            log::warn!("Propagating {:?} @ {:x}: {:#x?}", regnum, addr, reg_def);

                            // Does not seem to be needed here with the already
                            // existing SSA and reaching definition in place.
                            // Need further verification.

                            // rel.left_hand_side = Expr::Var(GenericLocation::Register(
                            //     reg_to_reg(idx, Size64).unwrap(),
                            // ));
                            // branch_prfs
                            //     .push(Proof::Hint("FuncPtrCalc".to_string(), Some(rel.clone())));
                        }
                    }

                    //2. propagate checked values on stack
                    for (stack_offset, stack_slot) in defs_state.stack.map.iter() {
                        if !checked_defs.is_empty() && (stack_slot.value == checked_defs) {
                            let vv = VarSlot {
                                size: stack_slot.size,
                                value: new_val.clone(),
                            };
                            branch_state.stack.map.insert(*stack_offset, vv);
                            // CARE: Did not model slot size here.

                            log::warn!(
                                "Propagating {:?} @ {:x}: {:#x?}",
                                regnum,
                                addr,
                                checked_defs
                            );
                            // Same as above, does not seem to be needed.
                            // rel.left_hand_side = Expr::Var(GenericLocation::Memory(
                            //     MemCellBuilder::new()
                            //         .base_reg(Register::RBP)
                            //         .displacement(*stack_offset)
                            //         .build(),
                            // ));
                            // branch_prfs.push(Proof::Rel(rel.clone()));
                        }
                    }

                    //3. resolve ptr thunks in registers
                    let checked_ptr = CallCheckValueLattice {
                        v: Some(PtrOffset(DAV::Checked)),
                    };
                    for idx in X86Regs::iter() {
                        let reg_val = branch_state.regs.get_reg(idx, Size64);
                        if let Some(PtrOffset(DAV::Unchecked(reg_def))) = reg_val.v {
                            if checked_defs.is_empty() && reg_def == checked_defs {
                                branch_state.regs.set_reg(idx, Size64, checked_ptr.clone());
                                log::debug!("Resolving ptr thunks {:?}", idx);
                                rel.lhs = Expr::Var(GenericLocation::Register(
                                    reg_to_reg(idx, Size64).unwrap(),
                                ));
                                rel.rhs = Expr::Const(Const::new(
                                    Sort::BitVec(64),
                                    "TableOffset".to_string(),
                                ));
                                branch_prfs.push(Proof::Hint(
                                    "FuncPtrCalc".to_string(),
                                    Some(rel.clone()),
                                ));
                            }
                        }
                    }

                    //4. resolve ptr thunks in stack slots --
                    for (stack_offset, stack_slot) in not_branch_state.stack.map.iter() {
                        let stack_val = stack_slot.value.v.clone();
                        if let Some(PtrOffset(DAV::Unchecked(stack_def))) = stack_val {
                            if !checked_defs.is_empty() && (stack_def == checked_defs) {
                                let v = VarSlot {
                                    size: stack_slot.size,
                                    value: checked_ptr.clone(),
                                };
                                branch_state.stack.map.insert(*stack_offset, v);
                                log::debug!("Resolving ptr thunks {:?}", stack_offset);
                                rel.lhs = Expr::Var(GenericLocation::Memory(
                                    MemCellBuilder::new()
                                        .base_reg(Register::RBP)
                                        .displacement(*stack_offset)
                                        .build(),
                                ));
                                rel.rhs = Expr::Const(Const::new(
                                    Sort::BitVec(64),
                                    "TableOffset".to_string(),
                                ));
                                branch_prfs.push(Proof::Hint(
                                    "FuncPtrCalc".to_string(),
                                    Some(rel.clone()),
                                ));
                            }
                        }
                    }
                }
            } else if is_je {
                //Handle TypeCheck
                if let Some(TypeCheckFlag(regnum, c)) = not_branch_state.regs.get_reg(Zf, Size64).v
                {
                    log::debug!(
                        "branch at 0x{:x}: TypeCheckFlag for reg {:?}. Making TypedPtrOffset({:?})",
                        addr,
                        regnum,
                        c
                    );
                    let new_val = CallCheckValueLattice {
                        v: Some(TypedPtrOffset(c)),
                    };
                    branch_state.regs.set_reg(regnum, Size64, new_val.clone());
                    let je_rel = rel!(
                        Expr::Var(GenericLocation::Register(
                            reg_to_reg(regnum, Size64).unwrap(),
                        )),
                        bv!("="),
                        Expr::Const(Const::new(Sort::BitVec(64), "TypedTableOffset".to_string(),))
                    );
                    // TODO BRANCH PRF ADD BACK WITH CORECT ADDR
                    branch_prfs.push(Proof::Hint("FuncPtrCalc".to_string(), Some(je_rel)));
                }
            }

            branch_state.regs.set_reg(Zf, Size64, Default::default());
            not_branch_state
                .regs
                .set_reg(Zf, Size64, Default::default());

            // NO NEED to generate clear flags proof, as flags clearing
            // are handled by the semantics extractor.

            // branch_prfs.push(Proof::Asgn(Assignment {
            //     left_hand_side: GenericLocation::Flag(Flags::ZF),
            //     right_hand_side: Expr::Any(size_to_size(&ValSize::Size1)),
            // }));
            // not_branch_prfs.push(Proof::Asgn(Assignment {
            //     left_hand_side: GenericLocation::Flag(Flags::ZF),
            //     right_hand_side: Expr::Any(size_to_size(&ValSize::Size1)),
            // }));

            log::debug!(
                " ->     branch_state @ 0x{:x} = {:?}",
                succ_addrs[1],
                branch_state
            );
            log::debug!(
                " -> not_branch_state @ 0x{:x} = {:?}",
                succ_addrs[0],
                not_branch_state
            );

            if flip {
                for prf in branch_prfs {
                    write_proof_to_file(prf, succ_addrs[0]);
                }
                for prf in not_branch_prfs {
                    write_proof_to_file(prf, succ_addrs[1]);
                }
                vec![
                    (succ_addrs[0].clone(), branch_state),
                    (succ_addrs[1].clone(), not_branch_state),
                ]
            } else {
                for prf in not_branch_prfs {
                    write_proof_to_file(prf, succ_addrs[0]);
                }
                for prf in branch_prfs {
                    write_proof_to_file(prf, succ_addrs[1]);
                }
                vec![
                    (succ_addrs[0].clone(), not_branch_state),
                    (succ_addrs[1].clone(), branch_state),
                ]
            }
        } else {
            succ_addrs
                .into_iter()
                .map(|addr| (addr.clone(), in_state.clone()))
                .collect()
        }
    }
}

// mem[LucetTableBase + 8]
pub fn is_table_size(in_state: &CallCheckLattice, memargs: &MemArgs) -> bool {
    if let MemArgs::Mem2Args(MemArg::Reg(regnum1, size), MemArg::Imm(_, _, 8)) = memargs {
        if let Some(LucetTablesBase) = in_state.regs.get_reg(*regnum1, *size).v {
            return true;
        }
    }
    false
}

pub fn is_fn_ptr(in_state: &CallCheckLattice, memargs: &MemArgs) -> Option<u32> {
    if let MemArgs::Mem3Args(
        MemArg::Reg(regnum1, size1),
        MemArg::Reg(regnum2, size2),
        MemArg::Imm(_, _, immval),
    ) = memargs
    {
        match (
            in_state.regs.get_reg(*regnum1, *size1).v,
            in_state.regs.get_reg(*regnum2, *size2).v,
            immval,
        ) {
            (Some(GuestTableBase), Some(TypedPtrOffset(c)), 8) => return Some(c),
            (Some(TypedPtrOffset(c)), Some(GuestTableBase), 8) => return Some(c),
            _ => return None,
        }
    }
    None
}

// returns none if not a typeof op
// returns Some(regnum) if result is type of regnum
pub fn is_typeof(in_state: &CallCheckLattice, memargs: &MemArgs) -> Option<X86Regs> {
    if let MemArgs::Mem2Args(MemArg::Reg(regnum1, size1), MemArg::Reg(regnum2, size2)) = memargs {
        match (
            in_state.regs.get_reg(*regnum1, *size1).v,
            in_state.regs.get_reg(*regnum2, *size2).v,
        ) {
            (Some(GuestTableBase), Some(PtrOffset(DAV::Checked))) => return Some(*regnum2),
            (Some(PtrOffset(DAV::Checked)), Some(GuestTableBase)) => return Some(*regnum1),
            _ => return None,
        }
    }
    None
}

impl CallAnalyzer {
    fn is_func_start(&self, addr: u64) -> bool {
        self.funcs.contains(&addr)
    }

    pub fn aeval_unop(&self, in_state: &CallCheckLattice, value: &Value) -> CallCheckValueLattice {
        match value {
            Value::Mem(memsize, memargs) => {
                if is_table_size(in_state, memargs) {
                    return CallCheckValueLattice { v: Some(TableSize) };
                } else if is_fn_ptr(in_state, memargs).is_some() {
                    let ty = is_fn_ptr(in_state, memargs).unwrap();
                    log::debug!("Making FnPtr({:?})", ty);
                    return CallCheckValueLattice { v: Some(FnPtr(ty)) };
                } else if is_typeof(in_state, memargs).is_some() {
                    let reg = is_typeof(in_state, memargs).unwrap();
                    log::debug!(
                        "Typeof operation: args: {:?} => r{:?} is base",
                        memargs,
                        reg
                    );
                    return CallCheckValueLattice {
                        v: Some(TypeOf(reg)),
                    };
                } else if is_stack_access(value) {
                    let offset = extract_stack_offset(memargs);
                    return in_state.stack.get(offset, memsize.into_bytes());
                }
            }

            Value::Reg(regnum, size) => return in_state.regs.get_reg(*regnum, *size),

            Value::Imm(_, _, immval) => {
                if (*immval as u64) == self.metadata.guest_table_0 {
                    return CallCheckValueLattice {
                        v: Some(GuestTableBase),
                    };
                } else if (*immval as u64) == self.metadata.lucet_tables {
                    return CallCheckValueLattice {
                        v: Some(LucetTablesBase),
                    };
                } else if self.is_func_start(*immval as u64) {
                    return CallCheckValueLattice {
                        v: Some(FnPtr(0xFFFF)), //dummy value, TODO remove
                    };
                } else {
                    return CallCheckValueLattice {
                        v: Some(Constant(*immval as u64)),
                    };
                }
            }

            Value::RIPConst => {
                // The backend uses rip-relative data to embed constant function pointers.
                return CallCheckValueLattice {
                    v: Some(FnPtr(0xFFFF)), //Dummy value, TODO remove
                };
            }
        }
        Default::default()
    }

    //checked_val << 4
    pub fn aeval_binop(
        &self,
        in_state: &CallCheckLattice,
        opcode: &Binopcode,
        src1: &Value,
        src2: &Value,
        loc_idx: &LocIdx,
    ) -> CallCheckValueLattice {
        if let Binopcode::Shl = opcode {
            if let (Value::Reg(regnum1, size1), Value::Imm(_, _, 4)) = (src1, src2) {
                if let Some(CheckedVal) = in_state.regs.get_reg(*regnum1, *size1).v {
                    return CallCheckValueLattice {
                        v: Some(PtrOffset(DAV::Checked)),
                    };
                } else {
                    let def_state = self
                        .reaching_analyzer
                        .fetch_def(&self.reaching_defs, loc_idx);
                    let reg_def = def_state.regs.get_reg(*regnum1, *size1);
                    return CallCheckValueLattice {
                        v: Some(PtrOffset(DAV::Unchecked(reg_def))),
                    };
                }
            }
        }
        Default::default()
    }
}
