use crate::analyses::*;
use crate::{analyses, ir, lattices, loaders};
use analyses::{AbstractAnalyzer, AnalysisResult};
use ir::types::{Binopcode, MemArg, MemArgs, Stmt, Unopcode, ValSize, Value, X86Regs};
use ir::utils::{extract_stack_offset, is_frame_access, is_stack_access};
use lattices::heaplattice::{HeapLattice, HeapValue, HeapValueLattice};
use lattices::reachingdefslattice::LocIdx;
use lattices::{ConstLattice, VarState};
use loaders::types::VwMetadata;
use ptir::*;
use std::default::Default;
use std::fmt::{format, Binary};
use std::fs;
use std::io::prelude::*;

use HeapValue::*;
use ValSize::*;
use X86Regs::*;

pub struct HeapAnalyzer {
    pub metadata: VwMetadata,
}

impl AbstractAnalyzer<HeapLattice> for HeapAnalyzer {
    fn init_state(&self) -> HeapLattice {
        let mut result: HeapLattice = Default::default();
        result
            .regs
            .set_reg(Rdi, Size64, HeapValueLattice::new(HeapBase));
        result
    }

    fn aexec(&self, in_state: &mut HeapLattice, ir_instr: &Stmt, loc_idx: &LocIdx) -> () {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(true) // This is needed to append to file
            .open("log.prf")
            .unwrap();
        match ir_instr {
            Stmt::Clear(dst, _srcs) => {
                if let &Value::Reg(rd, Size32) | &Value::Reg(rd, Size16) | &Value::Reg(rd, Size8) =
                    dst
                {
                    in_state
                        .regs
                        .set_reg(rd, Size64, HeapValueLattice::new(Bounded4GB));
                    log::info!("Clearing reg [{:?} = ANY]", rd);
                    // The implicication here is that flags are always 4GB-bounded.
                    // So no proof needs to be generated.
                    if !rd.is_flag() {
                        let relation = Relationship {
                            relationship: ptir::BinaryOp::BV(BVBinaryOp::Relation(
                                BVBinaryRelation::Ult,
                            )),
                            lhs: Expr::Var(
                                LocationBuilder::new()
                                    .register(reg_to_reg(rd, Size64).unwrap())
                                    .build(),
                            ),
                            rhs: Expr::Imm(Imm::from(u64::pow(2, 32))),
                        };
                        let proof: Proof = Proof::Rel(relation);
                        log::info!(
                            "PROOF[0x{:x}: {}]",
                            loc_idx.addr,
                            proof.output_prf().to_string()
                        );
                        file.write_all(
                            format!("0x{:x}: {}\n", loc_idx.addr, proof.output_prf()).as_bytes(),
                        )
                        .expect("cannot write to file");
                    }
                } else {
                    in_state.set_to_bot(dst);
                    // Same implication as above.
                    log::info!("Clearing dst [{:?} = ANY]", dst);
                    // if let &Value::Mem(_, _) = dst {
                    //     panic!("Clearing mem to bottom. Unseen case.");
                    // }
                }
            }
            Stmt::Unop(opcode, dst, src) => self.aexec_unop(in_state, opcode, &dst, &src, loc_idx),
            Stmt::Binop(opcode, dst, src1, src2) => {
                self.aexec_binop(in_state, opcode, dst, src1, src2, loc_idx);
                match in_state.adjust_stack_offset(opcode, dst, src1, src2) {
                    Some(proof) => {
                        log::info!("Proof[0x{:x}: {}]", loc_idx.addr, proof.output_prf());
                        file.write_all(
                            format!("0x{:x}: {}\n", loc_idx.addr, proof.output_prf()).as_bytes(),
                        )
                        .expect("cannot write to file");
                    }
                    None => (),
                }
            }
            Stmt::Call(_) => {
                // TODO: this should only be for probestack
                // RDI is conserved on calls
                // let v = in_state.regs.get_reg(Rdi, Size64);
                in_state.on_call();
                // in_state.regs.set_reg(Rdi, Size64, v);
            }
            _ => (),
        }
    }

    fn aexec_unop(
        &self,
        in_state: &mut HeapLattice,
        opcode: &Unopcode,
        dst: &Value,
        src: &Value,
        loc_idx: &LocIdx,
    ) -> () {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(true) // This is needed to append to file
            .open("log.prf")
            .unwrap();
        // Any write to a 32-bit register will clear the upper 32 bits of the
        // containing 64-bit register.
        if let &Value::Reg(rd, Size32) = dst {
            in_state.regs.set_reg(
                rd,
                Size64,
                ConstLattice {
                    v: Some(Bounded4GB),
                },
            );
            log::info!("Clearing upper 32 bit [{:?} <= 4GB]", rd);
            let left = LocationBuilder::new()
                .register(reg_to_reg(rd, Size64).unwrap())
                .build();

            let right = Expr::Imm(Imm::from(0x100000000 as u64));

            let relation = Relationship {
                relationship: ptir::BinaryOp::BV(BVBinaryOp::Relation(BVBinaryRelation::Ult)),
                lhs: Expr::Var(left),
                rhs: right,
            };
            let proof: Proof = Proof::Rel(relation);
            log::info!(
                "PROOF[0x{:x}: {}]",
                loc_idx.addr,
                proof.output_prf().to_string()
            );
            file.write_all(format!("0x{:x}: {}\n", loc_idx.addr, proof.output_prf()).as_bytes())
                .expect("cannot write to file");
            return;
        }

        match opcode {
            Unopcode::Mov => {
                let is_stack = is_stack_access(dst)
                    || is_stack_access(src)
                    || is_frame_access(dst)
                    || is_frame_access(src);

                let v = self.aeval_unop(in_state, src);
                in_state.set(dst, v.clone());
                log::info!("Mov assignment [{:?} = {:?}]", dst, src);
                let mut left_size = None;
                let left: Location = match dst {
                    Value::Mem(size, args) => {
                        if !is_stack {
                            return;
                        }
                        let mut mem = args_to_var(args);
                        mem.size = size_to_size(size);
                        LocationBuilder::new().memcell(mem).build()
                    }
                    Value::Reg(reg, size) => {
                        left_size = Some(size);
                        LocationBuilder::new()
                            .register(reg_to_reg(*reg, *size).unwrap())
                            .build()
                    }
                    _ => panic!("Unop mov: Unseen LHS cases"),
                };

                // log::debug!("left: {:#x?}, right: {:#x?}", left, v.clone());
                if v == HeapValueLattice::new(GlobalsBase) {
                    let rel = Relationship {
                        relationship: ptir::BinaryOp::BV(BVBinaryOp::Relation(
                            BVBinaryRelation::Eq,
                        )),
                        lhs: Expr::Var(left),
                        rhs: Expr::Const(Const::new(Sort::BitVec(64), "GlobalBase".to_string())),
                    };
                    log::debug!("Found global base relation {:?}", rel);
                    let prf = Proof::Hint("GlobalBaseLookup".to_string(), Some(rel));
                    //format!("HINT GlobalBaseLookup = {} GlobalBase", dst);
                    log::debug!("PROOF[0x{:x}: {}]", loc_idx.addr, prf.output_prf());
                    file.write_all(
                        format!("0x{:x}: {}\n", loc_idx.addr, prf.output_prf()).as_bytes(),
                    )
                    .expect("cannot write to file");
                }
                let right: Expr = match src {
                    Value::Mem(size, args) => {
                        if !is_stack {
                            return;
                        }
                        let mut mem = args_to_var(args);
                        mem.size = size_to_size(size);
                        Expr::Var(LocationBuilder::new().memcell(mem).build())
                    }
                    Value::Reg(reg, size) => Expr::Var(
                        LocationBuilder::new()
                            .register(reg_to_reg(*reg, *size).unwrap())
                            .build(),
                    ),
                    Value::Imm(sign, size, val) => Expr::Imm(Imm {
                        value: *val as u64,
                        size: match left_size {
                            Some(l) => {
                                if l > size {
                                    size_to_size(l)
                                } else {
                                    size_to_size(&size)
                                }
                            }
                            _ => size_to_size(&size),
                        },
                    }),
                    Value::RIPConst => {
                        let rel: Relationship = Relationship {
                            relationship: ptir::BinaryOp::BV(BVBinaryOp::Relation(
                                BVBinaryRelation::Eq,
                            )),
                            lhs: Expr::Var(left),
                            rhs: Expr::Const(Const::new(Sort::BitVec(64), "FnPtr".to_string())),
                        };
                        log::debug!("Found RIP const relation {:?}", rel);
                        output_proof_hint("RIPConst".to_string(), Some(rel), loc_idx.addr);
                        return;
                    }
                };
                let assignment = Assignment::new(left, right);
                let proof: Proof = Proof::Asgn(assignment);
                log::info!(
                    "PROOF[0x{:x}: {}]",
                    loc_idx.addr,
                    proof.output_prf().to_string()
                );
                file.write_all(
                    format!("0x{:x}: {}\n", loc_idx.addr, proof.output_prf()).as_bytes(),
                )
                .expect("cannot write to file");
            }
            Unopcode::Movsx => {
                in_state.set(dst, Default::default());
                log::info!("Movsx assignment [{:?} = {:?}]", dst, src);
                // panic!("MOVSX, Unseen case.");
            }
        }
    }

    fn aexec_binop(
        &self,
        in_state: &mut HeapLattice,
        opcode: &Binopcode,
        dst: &Value,
        src1: &Value,
        src2: &Value,
        _loc_idx: &LocIdx,
    ) {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .append(true) // This is needed to append to file
            .open("log.prf")
            .unwrap();
        match opcode {
            Binopcode::Add => {
                if let (
                    &Value::Reg(rd, Size64),
                    &Value::Reg(rs1, Size64),
                    &Value::Reg(rs2, Size64),
                ) = (dst, src1, src2)
                // rd = rdi + rbx;
                // rd = rdi + ffffffffffffffff;
                {
                    let rs1_val = in_state.regs.get_reg(rs1, Size64).v;
                    let rs2_val = in_state.regs.get_reg(rs2, Size64).v;
                    match (rs1_val, rs2_val) {
                        (Some(HeapBase), Some(Bounded4GB)) | (Some(Bounded4GB), Some(HeapBase)) => {
                            in_state
                                .regs
                                .set_reg(rd, Size64, ConstLattice { v: Some(HeapAddr) });
                            log::info!("Add assignment of form (DST = HeapBase + 4GBounded) [{:?} = {:?} + {:?}]", dst, src1, src2);

                            let left = LocationBuilder::new()
                                .register(reg_to_reg(rd, Size64).unwrap())
                                .build();

                            let src1 = LocationBuilder::new()
                                .register(reg_to_reg(rs1, Size64).unwrap())
                                .build();

                            let src2 = LocationBuilder::new()
                                .register(reg_to_reg(rs2, Size64).unwrap())
                                .build();

                            let right: Expr = Expr::Binary(
                                ptir::BinaryOp::BV(BVBinaryOp::Arith(BVBinaryArith::Add)),
                                Box::new(Expr::Var(src1)),
                                Box::new(Expr::Var(src2)),
                            );

                            let assign = Assignment::new(left, right);

                            let proof: Proof = Proof::Asgn(assign);
                            log::info!(
                                "PROOF[0x{:x}: {}]",
                                _loc_idx.addr,
                                proof.output_prf().to_string()
                            );
                            file.write_all(
                                format!("0x{:x}: {}\n", _loc_idx.addr, proof.output_prf())
                                    .as_bytes(),
                            )
                            .expect("cannot write to file");
                            return;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        // Any write to a 32-bit register will clear the upper 32 bits of the containing 64-bit
        // register.
        if let &Value::Reg(rd, Size32) = dst {
            in_state.regs.set_reg(
                rd,
                Size64,
                ConstLattice {
                    v: Some(Bounded4GB),
                },
            );
            log::info!("Clearing upper 32 bit (write) [{:?} <= 4GB]", rd);

            let left = LocationBuilder::new()
                .register(reg_to_reg(rd, Size64).unwrap())
                .build();

            let right = Expr::Imm(Imm::from(0x100000000 as u64));

            let relation = Relationship {
                relationship: ptir::BinaryOp::BV(BVBinaryOp::Relation(BVBinaryRelation::Ult)),
                lhs: Expr::Var(left),
                rhs: right,
            };
            let proof: Proof = Proof::Rel(relation);
            log::info!(
                "PROOF[0x{:x}: {}]",
                _loc_idx.addr,
                proof.output_prf().to_string()
            );
            file.write_all(format!("0x{:x}: {}\n", _loc_idx.addr, proof.output_prf()).as_bytes())
                .expect("cannot write to file");
            return;
        }

        in_state.set_to_bot(dst);
        log::info!("Binop setting [{:?} = BOTTOM]", dst);

        if let &Value::Reg(rd, size) = dst {
            match reg_to_reg(rd, size) {
                Some(reg) => {
                    let left = LocationBuilder::new().register(reg).build();

                    let right = Expr::Imm(Imm::from(0x100000000 as u64));

                    let relation = Relationship {
                        relationship: ptir::BinaryOp::BV(BVBinaryOp::Relation(
                            BVBinaryRelation::Ult,
                        )),
                        lhs: Expr::Var(left),
                        rhs: right,
                    };
                    let proof: Proof = Proof::Rel(relation);
                    log::info!(
                        "PROOF[0x{:x}: {}]",
                        _loc_idx.addr,
                        proof.output_prf().to_string()
                    );
                    // file.write_all(
                    //     format!("0x{:x}: {}\n", _loc_idx.addr, proof.output_prf()).as_bytes(),
                    // )
                    // .expect("cannot write to file");
                }
                None => {
                    let left = LocationBuilder::new().flag(reg_to_flags(rd)).build();

                    let right = Expr::Imm(Imm::from(0x100000000 as u64));

                    let relation = Relationship {
                        relationship: ptir::BinaryOp::BV(BVBinaryOp::Relation(
                            BVBinaryRelation::Ult,
                        )),
                        lhs: Expr::Var(left),
                        rhs: right,
                    };
                    let proof: Proof = Proof::Rel(relation);
                    log::info!(
                        "PROOF[0x{:x}: {}]",
                        _loc_idx.addr,
                        proof.output_prf().to_string()
                    );
                    // file.write_all(
                    //     format!("0x{:x}: {}\n", _loc_idx.addr, proof.output_prf()).as_bytes(),
                    // )
                    // .expect("cannot write to file");
                }
            }
        } else {
            panic!("Unhandled case");
        }
    }

    fn process_branch(
        &self,
        _irmap: &ir::types::IRMap,
        in_state: &HeapLattice,
        succ_addrs: &Vec<u64>,
        _addr: &u64,
    ) -> Vec<(u64, HeapLattice)> {
        succ_addrs
            .into_iter()
            .map(|addr| (addr.clone(), in_state.clone()))
            .collect()
    }

    fn analyze_block(&self, state: &HeapLattice, irblock: &ir::types::IRBlock) -> HeapLattice {
        let mut new_state = state.clone();
        for (addr, instruction) in irblock.iter() {
            for (idx, ir_insn) in instruction.iter().enumerate() {
                log::trace!(
                    "Analyzing insn @ 0x{:x}: {:?}: state = {:#?}",
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

pub fn is_globalbase_access(in_state: &HeapLattice, memargs: &MemArgs) -> bool {
    if let MemArgs::Mem2Args(arg1, _arg2) = memargs {
        if let MemArg::Reg(regnum, size) = arg1 {
            assert_eq!(size.into_bits(), 64);
            let base = in_state.regs.get_reg(*regnum, *size);
            if let Some(HeapBase) = base.v {
                return true;
            }
        }
    };
    false
}

impl HeapAnalyzer {
    pub fn aeval_unop(&self, in_state: &HeapLattice, value: &Value) -> HeapValueLattice {
        match value {
            Value::Mem(memsize, memargs) => {
                if is_globalbase_access(in_state, memargs) {
                    return HeapValueLattice::new(GlobalsBase);
                }
                if is_stack_access(value) {
                    let offset = extract_stack_offset(memargs);
                    let v = in_state.stack.get(offset, memsize.into_bytes());
                    return v;
                }
            }

            Value::Reg(regnum, size) => {
                if size.into_bits() <= 32 {
                    return HeapValueLattice::new(Bounded4GB);
                } else {
                    return in_state.regs.get_reg(*regnum, Size64);
                }
            }

            Value::Imm(_, _, immval) => {
                if (*immval as u64) == self.metadata.guest_table_0 {
                    return HeapValueLattice::new(GuestTable0);
                } else if (*immval as u64) == self.metadata.lucet_tables {
                    return HeapValueLattice::new(LucetTables);
                } else if (*immval >= 0) && (*immval < (1 << 32)) {
                    return HeapValueLattice::new(Bounded4GB);
                }
            }

            Value::RIPConst => {
                return HeapValueLattice::new(RIPConst);
            }
        }
        Default::default()
    }
}
