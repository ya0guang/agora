pub mod wasmsfi;
use iced_asm::{Instruction, Mnemonic};
use object::{Object, ObjectSection, ObjectSymbol, Symbol, SymbolKind};
pub use wasmsfi::*;
pub mod lfence;
pub use lfence::*;

use crate::dis::{ControlFlowInfo, Disassembled};
use crate::solve::unify_ssexprs;
use crate::ssa::{FuncSSA, InsSSA};
use crate::validate::{expr_to_ssexpr, AssertWithInfo, TotalProof};
use anyhow::{anyhow, Result};
use ir::*;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

pub type HintAssertWithInfo = (Vec<AssertWithInfo>, AssertWithInfo);

pub struct Verifier {
    pub policy: Policy,
    pub binary_type: BinaryType,
    binary: Vec<u8>,
    pub solverless: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum BinaryType {
    Lucet,
    Elf,
}

impl FromStr for BinaryType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "lucet" => Ok(BinaryType::Lucet),
            "elf" => Ok(BinaryType::Elf),
            _ => Err(anyhow!("Invalid binary type")),
        }
    }
}

impl BinaryType {
    pub fn is_wasm(&self) -> bool {
        match self {
            BinaryType::Lucet => true,
            BinaryType::Elf => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Policy {
    WasmSFI,
    LfenceAfterLoad,
}

impl FromStr for Policy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s == "WasmSFI" || s == "wasm" {
            Ok(Policy::WasmSFI)
        } else if s == "LfenceAfterLoad" || s == "lfence" {
            Ok(Policy::LfenceAfterLoad)
        } else {
            Err(anyhow::anyhow!("Unknown policy: {}", s))
        }
    }
}

impl Verifier {
    pub fn new(policy: Policy, binary_type: BinaryType, binary: Vec<u8>, solverless: bool) -> Self {
        Verifier {
            policy,
            binary_type,
            binary,
            solverless,
        }
    }

    pub fn dummy() -> Self {
        Verifier {
            policy: Policy::WasmSFI,
            binary_type: BinaryType::Lucet,
            binary: vec![],
            solverless: false,
        }
    }

    pub fn verify(
        &self,
        ssa: &FuncSSA,
        dis: &Disassembled,
        proofs: &BTreeMap<u64, TotalProof>,
        constraints: &mut BTreeMap<u64, Constraints>,
        cfi: &ControlFlowInfo,
    ) -> Result<()> {
        let object = object::File::parse(&*self.binary)?;
        let mapping: HashMap<String, Symbol> = object
            .symbols()
            .map(|s| (s.name().unwrap().to_string(), s))
            .collect();
        let mut func_ptrs = HashMap::new();
        let mut got_ptrs = HashSet::new();
        for (name, sym) in &mapping {
            match sym.kind() {
                SymbolKind::Text => {
                    func_ptrs.insert(name.clone(), sym.address());
                }
                _ => {}
            }
        }
        let got_sec = object.section_by_name(".got").unwrap();
        for ptr_memory in (got_sec.address()..got_sec.address() + got_sec.size()).step_by(8) {
            got_ptrs.insert(ptr_memory);
        }
        // println!("func_ptrs: {:x?}", func_ptrs);
        // println!("got_ptrs: {:x?}", got_ptrs);

        let lucet_tables = mapping.get("lucet_tables").unwrap();
        let sec = object.section_by_index(lucet_tables.section_index().unwrap())?;
        let lucet_tables_size = u64::from_le_bytes(
            sec.data_range(lucet_tables.address() + 8, 8)?
                .unwrap()
                .try_into()
                .unwrap(),
        );
        // object.section_by_name("got").unwrap()
        // println!(
        //     "lucet_tables: {:x}, size: {}",
        //     lucet_tables.address(),
        //     lucet_tables_size
        // );
        match self.policy {
            Policy::WasmSFI => {
                MemAccessBounded::new(ssa).match_function(ssa, dis, proofs, constraints, cfi)?;
                IndirectJumpSafe::new().match_function(ssa, dis, proofs, constraints, cfi)?;
                IndirectCallSafe::new(
                    mapping.get("guest_table_0").unwrap().address(),
                    mapping.get("lucet_tables").unwrap().address(),
                    mapping.get("lucet_probestack").unwrap().address(),
                    lucet_tables_size,
                    func_ptrs,
                    got_ptrs,
                )
                .match_function(ssa, dis, proofs, constraints, cfi)
            }
            Policy::LfenceAfterLoad => {
                LfenceAfterLoad::new().match_function(ssa, dis, proofs, constraints, cfi)
            }
        }
    }
}

#[derive(Debug)]
pub struct Constraints {
    // the assertion need to be checked for true before any other constraints, derived from hints
    // After the preconditions are checked, the related `SSRel` (HintAssertWithInfo.2) will be added to the environment
    pub prf_preconditions: Vec<HintAssertWithInfo>,
    // assignments are always trusted
    pub sem_assignments: Vec<SSAsgn>,
    // relationships are not trusted, provided by the proof and validated by the solver
    // after checking the correctness of the relationships, it will be added to the environment
    pub prf_relationships: Vec<SSExpr>,
    // relationships from the semantics are trusted, provided by the policy to offer additional information to conduct the checking
    pub sem_relationships: Vec<AssertWithInfo>,
    // SMT constraints matched by the policy checker with debug info (checked relationships)
    pub assertions: Vec<AssertWithInfo>,
    pub constants: HashSet<Const>,
    // The assumptions derived from branch conditions
    // This information should be added to the stack when checking precondition
    pub branch_conditions: Vec<SSExpr>,
}

impl Constraints {
    pub fn init(source: &TotalProof) -> Constraints {
        Constraints {
            prf_preconditions: vec![],
            sem_assignments: source.sem_assignments.clone(),
            prf_relationships: source
                .prf_relationships
                .iter()
                .map(|x| x.clone().into())
                .collect(),
            sem_relationships: source
                .sem_relationships
                .iter()
                .map(|x| (x.clone().into(), format!("relationship from the semantics")))
                .collect(),
            assertions: vec![],
            constants: HashSet::new(),
            branch_conditions: vec![],
        }
    }
}

pub type _Matcher = fn(
    &FuncSSA,
    &Disassembled,
    &BTreeMap<u64, TotalProof>,
    &mut BTreeMap<u64, Constraints>,
    &HashMap<u64, Vec<Proof>>,
) -> Result<()>;

pub trait Matcher {
    fn match_function(
        &self,
        ssa: &FuncSSA,
        dis: &Disassembled,
        proofs: &BTreeMap<u64, TotalProof>,
        constraints: &mut BTreeMap<u64, Constraints>,
        cfi: &ControlFlowInfo,
    ) -> Result<()>;

    // fn init(ssa: &FuncSSA) -> Self;
    fn resolve_flags(
        &self,
        ins: &Instruction,
        // ins_cons: &mut Constraints,
        // cfi: &ControlFlowInfo,
        // addr: &u64,
        ins_ssa: &InsSSA,
    ) -> Result<SSExpr> {
        match ins.mnemonic() {
            Mnemonic::Jae
            | Mnemonic::Ja
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Je
            | Mnemonic::Jne => {
                let jump_cond = match ins.mnemonic() {
                    Mnemonic::Jae => expr_to_ssexpr(
                        &GenericExpr::Var(Location::Flag(Flags::CF)).negate(),
                        &ins_ssa.ssa,
                    ),
                    Mnemonic::Ja => Ok(unify_ssexprs(
                        &(vec![
                            expr_to_ssexpr(
                                &GenericExpr::Var(Location::Flag(Flags::CF)).negate(),
                                &ins_ssa.ssa,
                            )?,
                            expr_to_ssexpr(
                                &GenericExpr::Var(Location::Flag(Flags::ZF)).negate(),
                                &ins_ssa.ssa,
                            )?,
                        ]),
                        boolean!("and"),
                    )),
                    Mnemonic::Jb => {
                        expr_to_ssexpr(&GenericExpr::Var(Location::Flag(Flags::CF)), &ins_ssa.ssa)
                    }
                    Mnemonic::Jbe => Ok(unify_ssexprs(
                        &(vec![
                            expr_to_ssexpr(
                                &GenericExpr::Var(Location::Flag(Flags::CF)),
                                &ins_ssa.ssa,
                            )?,
                            expr_to_ssexpr(
                                &GenericExpr::Var(Location::Flag(Flags::ZF)),
                                &ins_ssa.ssa,
                            )?,
                        ]),
                        boolean!("or"),
                    )),
                    Mnemonic::Je => {
                        expr_to_ssexpr(&GenericExpr::Var(Location::Flag(Flags::ZF)), &ins_ssa.ssa)
                    }
                    Mnemonic::Jne => expr_to_ssexpr(
                        &GenericExpr::Var(Location::Flag(Flags::ZF)).negate(),
                        &ins_ssa.ssa,
                    ),
                    _ => panic!("Unreachable"),
                };
                jump_cond
                // let jump_assumption = expr!(
                //     jump_cond.clone(),
                //     bv!("="),
                //     Const::new(
                //         Sort::Bool,
                //         format!(
                //             "br_cond_{:x}_{:x}",
                //             find_site_bb(&cfi.basic_blocks, *addr)?,
                //             ins.memory_displacement64()
                //         )
                //     )
                //     .into()
                // );
                // log::warn!("cfi_assumption: {:?}", jump_assumption.clone());
                // ins_cons
                //     .assumptions
                //     .push((jump_assumption, format!("CFI assumption on {:x}", addr)));

                // let not_jump_assumption = expr!(
                //     jump_cond.clone().negate(),
                //     bv!("="),
                //     Const::new(
                //         Sort::Bool,
                //         format!(
                //             "br_cond_{:x}_{:x}",
                //             find_site_bb(&cfi.basic_blocks, *addr)?,
                //             ins.next_ip()
                //         )
                //     )
                //     .into()
                // );
                // ins_cons
                //     .assumptions
                //     .push((not_jump_assumption, format!("CFI assumption on {:x}", addr)));
            }
            _ => Err(anyhow!("should not reach here")),
        }
        // Ok(())
    }
}
