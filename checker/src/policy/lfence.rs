use super::Matcher;
use crate::dis::ControlFlowInfo;
use crate::dis::Disassembled;
use crate::policy::Constraints;
use crate::ssa::*;
use crate::validate::*;
use anyhow::Result;
use iced_asm::{InstructionInfoFactory, Mnemonic, OpAccess};
use ir::*;
use lazy_static::lazy_static;
use std::collections::{BTreeMap, HashSet};

// These instructions don't need to be fenced after
lazy_static! {
    static ref AVOID_FENCE_AFTER: HashSet<Mnemonic> = {
        let mut set = HashSet::new();
        set.insert(Mnemonic::Ret);
        set.insert(Mnemonic::Call);
        set.insert(Mnemonic::Pop);
        set.insert(Mnemonic::Push);
        set.insert(Mnemonic::Lfence);
        set.insert(Mnemonic::Leave);
        set
    };
}

pub struct LfenceAfterLoad {}

impl LfenceAfterLoad {
    pub fn new() -> Self {
        LfenceAfterLoad {}
    }
}

// fn _lfence_const(addr: u64) -> Const {
//     Const::new(Sort::Bool, format!("clfence_0x{:x}", addr))
// }

impl Matcher for LfenceAfterLoad {
    fn match_function(
        &self,
        ssa: &FuncSSA,
        dis: &Disassembled,
        _proofs: &BTreeMap<u64, TotalProof>,
        constraints: &mut BTreeMap<u64, Constraints>,
        _cfi: &ControlFlowInfo,
    ) -> Result<()> {
        // Will be removed after features are stabilized
        let mut _last_fence = false;
        let mut next_should_fence = false;

        // to check `lfence` inserted before
        let mut _last_addr: u64 = 0;

        for (addr, ins) in dis {
            if next_should_fence {
                let ins_cons = constraints.get_mut(addr).unwrap();
                ins_cons.assertions.push((
                    expr!(
                        expr_to_ssexpr(
                            &Location::MAS(MicroArchitecturalState::LoadBuffer).into(),
                            &ssa.ssa_map.get(addr).unwrap().ssa
                        )?,
                        boolean!("="),
                        Imm::new(0, ValSize::Size1).into()
                    ),
                    format!("Lfence After Load check @ 0x{:x}", addr),
                ));
                next_should_fence = false;
            }

            let mut info_factory = InstructionInfoFactory::new();
            let info = info_factory.info(&ins);
            if !AVOID_FENCE_AFTER.contains(&ins.mnemonic())
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
                next_should_fence = true;
                continue;
            }
        }
        Ok(())
    }
}
