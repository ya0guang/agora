use crate::{analyses, ir, lattices};
use analyses::AbstractAnalyzer;
use ir::types::{Binopcode, Stmt, Unopcode};
use ir::utils::{get_imm_offset, is_rbp, is_rsp};
use lattices::reachingdefslattice::LocIdx;
use lattices::stackgrowthlattice::StackGrowthLattice;

pub struct StackAnalyzer {}

impl AbstractAnalyzer<StackGrowthLattice> for StackAnalyzer {
    fn init_state(&self) -> StackGrowthLattice {
        StackGrowthLattice::new((0, 4096, 0))
    }

    fn aexec(&self, in_state: &mut StackGrowthLattice, ir_instr: &Stmt, loc_idx: &LocIdx) -> () {
        log::debug!(
            "Stack analyzer: stmt at 0x{:x}: {:?} with state {:?}",
            loc_idx.addr,
            ir_instr,
            in_state
        );
        match ir_instr {
            Stmt::Clear(dst, _) => {
                if is_rsp(dst) {
                    *in_state = Default::default();
                    panic!("Havoc stack growth state at 0x{:x}", loc_idx.addr);
                }
            }
            Stmt::Unop(Unopcode::Mov, dst, src) if is_rsp(dst) && is_rbp(src) => {
                if let Some((_, probestack, rbp_stackgrowth)) = in_state.v {
                    *in_state = StackGrowthLattice {
                        v: Some((rbp_stackgrowth, probestack, rbp_stackgrowth)),
                    };
                    log::debug!("Mov, state at 0x[{:x}]: {:?}", loc_idx.addr, in_state);
                    log::debug!("Nothing needs to be done.");
                }
            }
            Stmt::Unop(Unopcode::Mov, dst, src) if is_rbp(dst) && is_rsp(src) => {
                if let Some((stackgrowth, probestack, _)) = in_state.v {
                    *in_state = StackGrowthLattice {
                        v: Some((stackgrowth, probestack, stackgrowth)),
                    };
                    log::debug!("Mov, state at 0x[{:x}]: {:?}", loc_idx.addr, in_state);
                    log::debug!("Nothing needs to be done.");
                }
            }
            Stmt::Unop(_, dst, _) => {
                if is_rsp(dst) {
                    *in_state = Default::default();
                    panic!("Havoc stack growth state at 0x{:x}", loc_idx.addr);
                }
            }
            Stmt::Binop(Binopcode::Cmp, _, _, _) => (),
            Stmt::Binop(Binopcode::Test, _, _, _) => (),
            Stmt::Binop(opcode, dst, src1, src2) => {
                if is_rsp(dst) {
                    if is_rsp(src1) {
                        log::debug!(
                            "Processing stack instruction: 0x{:x} {:?}",
                            loc_idx.addr,
                            ir_instr
                        );
                        let offset = get_imm_offset(src2);
                        if let Some((x, probestack, rbp)) = in_state.v {
                            match opcode {
                                Binopcode::Add => {
                                    *in_state = StackGrowthLattice {
                                        v: Some((x + offset, probestack, rbp)),
                                    };
                                    log::debug!(
                                        "Add, state at 0x[{:x}]: {:?}",
                                        loc_idx.addr,
                                        in_state
                                    );
                                }
                                Binopcode::Sub => {
                                    if (offset - x) > probestack + 4096 {
                                        panic!("Probestack violation")
                                    } else if (offset - x) > probestack {
                                        //if we touch next page after the space
                                        //we've probed, it cannot skip guard page
                                        *in_state = StackGrowthLattice {
                                            v: Some((x - offset, probestack + 4096, rbp)),
                                        };
                                        log::debug!(
                                            "Sub, probestack state at 0x[{:x}]: {:?}",
                                            loc_idx.addr,
                                            in_state
                                        );
                                        return;
                                    }
                                    *in_state = StackGrowthLattice {
                                        v: Some((x - offset, probestack, rbp)),
                                    };
                                    log::debug!(
                                        "Sub, state at 0x[{:x}]: {:?}",
                                        loc_idx.addr,
                                        in_state
                                    );
                                }
                                _ => panic!("Illegal RSP write"),
                            }
                        } else {
                            *in_state = Default::default()
                        }
                    } else {
                        *in_state = Default::default()
                    }
                }
            }
            Stmt::ProbeStack(new_probestack) => {
                if let Some((x, _old_probestack, rbp)) = in_state.v {
                    let probed = (((*new_probestack / 4096) + 1) * 4096) as i64; // Assumes page size of 4096
                    *in_state = StackGrowthLattice {
                        v: Some((x - *new_probestack as i64, probed, rbp)),
                    }
                } else {
                    *in_state = Default::default()
                }
            }
            _ => (),
        }
    }
}
