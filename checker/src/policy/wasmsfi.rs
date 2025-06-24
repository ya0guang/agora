use super::Matcher;
use crate::dis::{find_site_bb, ControlFlowInfo, Disassembled};
use crate::policy::Constraints;
use crate::semantics::*;
use crate::solve::*;
use crate::ssa::*;
use crate::validate::*;
use anyhow::{anyhow, Result};
use iced_asm::Mnemonic;
use ir::*;
use lazy_static::lazy_static;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::vec;

// TODO: specify the Policy
// pub struct Policy;

// pub struct InsMatcher {
//     /// OPCode type, can be empty
//     mnemonics: Vec<Mnemonic>,
//     /// matching operands
//     operand: Vec<OperandMatcher>,
//     /// Specify the previous instruction that need to be matched, could be chained
//     previous: Option<Box<InsMatcher>>,
//     /// Specify the next instruction that need to be matched, could be chained
//     next: Option<Box<InsMatcher>>,
// }

// pub struct OperandMatcher {
//     /// The position of the operand (e.g., to identify destination/source), ignored to match all operands
//     position: Option<u8>,
//     /// kind of the operand
//     kind: operandKind,
//     /// specify Register used, ignored when matching imm
//     registers: Vec<Register>,
//     /// specify how this operand is accessed
//     access: OpAccess,
//     // size: Option<u64>,
// }

// pub enum operandKind {
//     Imm,
//     Reg,
//     Mem,
//     Addr,
// }

pub struct IndirectJumpSafe {}

impl IndirectJumpSafe {
    pub fn new() -> Self {
        IndirectJumpSafe {}
    }
}

impl Matcher for IndirectJumpSafe {
    fn match_function(
        &self,
        ssa: &FuncSSA,
        dis: &Disassembled,
        proofs: &BTreeMap<u64, TotalProof>,
        constraints: &mut BTreeMap<u64, Constraints>,
        _cfi: &ControlFlowInfo,
    ) -> Result<()> {
        let dummy_guard = constraints.iter_mut().next().unwrap().1;
        let jmp_tar_dummy = Const::new(Sort::BitVec(64), format!("jmp_tar_dummy"));
        dummy_guard.constants.insert(jmp_tar_dummy.clone());
        let mut _possible_jmp_tar: HashSet<Const> =
            vec![jmp_tar_dummy.clone()].into_iter().collect();

        let mut branch_cond_target_sources: BTreeMap<u64, BTreeMap<u64, SSExpr>> = BTreeMap::new();
        for (addr, ins_ssa) in &ssa.ssa_map {
            let ins = dis.get(addr).unwrap();
            if ins_ssa.ss_asgns.len() == 1 {
                match ins.mnemonic() {
                    Mnemonic::Jae
                    | Mnemonic::Ja
                    | Mnemonic::Jb
                    | Mnemonic::Jbe
                    | Mnemonic::Je
                    | Mnemonic::Jne => {
                        let jump_cond: SSExpr = self.resolve_flags(ins, ins_ssa)?;
                        branch_cond_target_sources
                            .entry(ins.memory_displacement64())
                            .or_insert(BTreeMap::new())
                            .insert(*addr, jump_cond.clone());
                        branch_cond_target_sources
                            .entry(ins.next_ip())
                            .or_insert(BTreeMap::new())
                            .insert(*addr, jump_cond.clone().negate());
                    }
                    _ => {}
                }
            }
        }

        // TODO may not be precisely correct, indirect call has similar problem,
        // can be addressed later
        let mut last_idx = Const::new(Sort::BitVec(64), format!("dummy"));

        for (addr, ins_ssa) in &ssa.ssa_map {
            let ins = dis.get(addr).unwrap();
            let ins_proof = proofs.get(addr).unwrap();
            let ins_cons = constraints.get_mut(addr).unwrap();

            let mut hint_assertions = vec![];
            for (policy_name, hint_rel) in &ins_proof.hints {
                match policy_name.as_str() {
                    "JmpPtrCalc" => {
                        let hint_rel = hint_rel.as_ref().unwrap();
                        if let GenericExpr::Const(ptr_calc_const) = hint_rel.rhs.clone() {
                            let mut tokens = ptr_calc_const.name.split("_").fuse();
                            let name = tokens.next().unwrap();
                            let number = tokens.next().unwrap();

                            match name {
                                "JmpIdx" => (),
                                _ => {
                                    let mov_dst = location_operand(ins, 0)?;
                                    let rhs_sort = hint_rel.lhs.infer_sort()?;
                                    let dst_check = expr!(
                                        expr_to_ssexpr(
                                            &mov_dst.get_sort().cast(rhs_sort)?(tease_expr(
                                                mov_dst.into(),
                                                None
                                            )?),
                                            &ins_ssa.ssa
                                        )?,
                                        bv!("="),
                                        hint_rel.lhs.clone()
                                    );
                                    hint_assertions.push((
                                        dst_check,
                                        format!(
                                            "destination check of FuncPtrCalc hint at 0x{:X}",
                                            addr
                                        ),
                                    ));
                                }
                            }

                            match name {
                                "JmpIdx" => {
                                    let bound = u64::from_str_radix(&number, 16)?;
                                    if bound == 0 {
                                        continue;
                                    }

                                    let bb_head = find_site_bb(&_cfi.basic_blocks, *addr)?;
                                    let conds = branch_cond_target_sources.get(&bb_head).unwrap();
                                    for c in conds {
                                        ins_cons.branch_conditions.push(c.1.clone());
                                    }

                                    let check = vec![(
                                        expr!(
                                            hint_rel.lhs.clone(),
                                            bv!("bvult"),
                                            Imm::from(bound).into()
                                        ),
                                        "Checking JmpIdx hint".to_string(),
                                    )];
                                    let jmp_idx =
                                        Const::new(Sort::BitVec(64), format!("JmpIdx_{:x}", addr));
                                    ins_cons.constants.insert(jmp_idx.clone());
                                    ins_cons.prf_preconditions.push((
                                        check,
                                        (
                                            expr!(
                                                hint_rel.lhs.clone(),
                                                bv!("="),
                                                jmp_idx.clone().into()
                                            ),
                                            "JmpIdx hint checked".to_string(),
                                        ),
                                    ));
                                    last_idx = jmp_idx.clone();
                                }
                                "JmpOffset" => {
                                    let base = u64::from_str_radix(&number, 16)?;
                                    let mov_addr =
                                        match &ins_ssa.ss_asgns.iter().next().unwrap().rhs {
                                            GenericExpr::Var(x) => {
                                                if let GenericLocation::Memory(m) = &x.loc {
                                                    m.take_address()?
                                                } else {
                                                    panic!("src of mov is not memory")
                                                }
                                            }
                                            _ => return Err(anyhow!("src of mov is not memory")),
                                        };

                                    let real: SSExpr = expr!(
                                        expr!(
                                            last_idx.clone().into(),
                                            bv!("bvmul"),
                                            Imm::from(4u64).into()
                                        ),
                                        bv!("bvadd"),
                                        GenericExpr::Imm(Imm::from(base))
                                    );

                                    let check = vec![(
                                        expr!(mov_addr, bv!("="), real),
                                        "Checking JmpOffset hint".to_string(),
                                    )];
                                    // let jmp_offset = Const::new(
                                    //     Sort::BitVec(64),
                                    //     format!("JmpOffset_{:x}", addr),
                                    // );
                                    ins_cons.constants.insert(ptr_calc_const.clone());
                                    ins_cons.prf_preconditions.push((
                                        check,
                                        (
                                            expr!(
                                                hint_rel.lhs.clone(),
                                                bv!("="),
                                                ptr_calc_const.clone().into()
                                            ),
                                            "JmpOffset hint checked".to_string(),
                                        ),
                                    ));
                                }
                                "JmpTarget" => {
                                    let base = u64::from_str_radix(&number, 16)?;
                                    let real: SSExpr = expr!(
                                        Const::new(
                                            Sort::BitVec(64),
                                            format!("JmpOffset_{:x}", base)
                                        )
                                        .into(),
                                        bv!("bvadd"),
                                        Imm::from(base).into()
                                    );
                                    let check = vec![(
                                        expr!(hint_rel.lhs.clone(), bv!("="), real),
                                        "Checking JmpTarget hint".to_string(),
                                    )];
                                    ins_cons.constants.insert(ptr_calc_const.clone());
                                    ins_cons.prf_preconditions.push((
                                        check,
                                        (
                                            expr!(
                                                hint_rel.lhs.clone(),
                                                bv!("="),
                                                ptr_calc_const.clone().into()
                                            ),
                                            "JmpTarget hint checked".to_string(),
                                        ),
                                    ));
                                }
                                _ => panic!("Unreachable"),
                            }
                        }
                    }
                    _ => (),
                }
            }

            if ins.is_jmp_far_indirect() || ins.is_jmp_near_indirect() {
                let jump_target = expr_to_ssexpr(&expr_operand(ins, 0)?, &ins_ssa.ssa)?;
                let assertion = expr!(
                    jump_target.clone(),
                    bv!("="),
                    Const::new(Sort::BitVec(64), format!("JmpTarget_{:x}", ins.next_ip())).into()
                );
                let guardian_cons = constraints.iter_mut().next_back().unwrap().1;
                guardian_cons
                    .assertions
                    .push((assertion, "checking indirect jump target".to_string()));
            }
        }

        Ok(())
    }
}

pub struct IndirectCallSafe {
    pub guest_table_0: u64,
    pub lucet_tables: u64,
    pub lucet_probestack: u64,
    pub guest_table_0_size: u64,
    pub function_addresses: HashMap<String, u64>,
    pub function_pointer_addresses: HashSet<u64>,
}

lazy_static! {
    static ref LUCET_BASE: Const = Const::new(Sort::BitVec(64), "LucetTablesBase".to_string());
    static ref GUEST_BASE: Const = Const::new(Sort::BitVec(64), "GuestTableBase".to_string());
    static ref TABLE_SIZE: Const = Const::new(Sort::BitVec(64), "TableSize".to_string());
    static ref TABLE_IDX: Const = Const::new(Sort::BitVec(64), "TableIdx".to_string());
    static ref TYPED_TABLE_OFFSET: Const =
        Const::new(Sort::BitVec(64), "TypedTableOffset".to_string());
    static ref UNCHECKED_TABLE_OFFSET: Const =
        Const::new(Sort::BitVec(64), "UncheckedTableOffset".to_string());
}

impl IndirectCallSafe {
    pub fn new(
        guest_table_0: u64,
        lucet_tables: u64,
        lucet_probestack: u64,
        guest_table_0_size: u64,
        function_addresses: HashMap<String, u64>,
        function_pointer_addresses: HashSet<u64>,
    ) -> Self {
        IndirectCallSafe {
            guest_table_0,
            lucet_tables,
            lucet_probestack,
            guest_table_0_size,
            function_addresses,
            function_pointer_addresses,
        }
    }
}

impl Matcher for IndirectCallSafe {
    fn match_function(
        &self,
        ssa: &FuncSSA,
        dis: &Disassembled,
        proofs: &BTreeMap<u64, TotalProof>,
        constraints: &mut BTreeMap<u64, Constraints>,
        _cfi: &ControlFlowInfo,
    ) -> Result<()> {
        let dummy_guard = constraints.iter_mut().next().unwrap().1;
        dummy_guard.constants.insert(LUCET_BASE.clone());
        dummy_guard.constants.insert(GUEST_BASE.clone());
        dummy_guard.constants.insert(TABLE_SIZE.clone());
        dummy_guard.sem_relationships.push((
            expr!(
                LUCET_BASE.clone().into(),
                bv!("="),
                Imm::from(self.lucet_tables).into()
            ),
            "lucet_base".to_string(),
        ));
        dummy_guard.sem_relationships.push((
            expr!(
                GUEST_BASE.clone().into(),
                bv!("="),
                Imm::from(self.guest_table_0).into()
            ),
            "guest_base".to_string(),
        ));
        dummy_guard.sem_relationships.push((
            expr!(
                TABLE_SIZE.clone().into(),
                bv!("="),
                Imm::from(self.guest_table_0_size).into()
            ),
            "table_size".to_string(),
        ));

        let mut possible_fnptrs: HashSet<Const> = HashSet::new();
        let mut call_targets = vec![];

        let mut branch_cond_target_sources: BTreeMap<u64, BTreeMap<u64, SSExpr>> = BTreeMap::new();
        for (addr, ins_ssa) in &ssa.ssa_map {
            let ins = dis.get(addr).unwrap();
            if ins_ssa.ss_asgns.len() == 1 {
                match ins.mnemonic() {
                    Mnemonic::Jae
                    | Mnemonic::Ja
                    | Mnemonic::Jb
                    | Mnemonic::Jbe
                    | Mnemonic::Je
                    | Mnemonic::Jne => {
                        let jump_cond: SSExpr = self.resolve_flags(ins, ins_ssa)?;
                        branch_cond_target_sources
                            .entry(ins.memory_displacement64())
                            .or_insert(BTreeMap::new())
                            .insert(*addr, jump_cond.clone());
                        branch_cond_target_sources
                            .entry(ins.next_ip())
                            .or_insert(BTreeMap::new())
                            .insert(*addr, jump_cond.clone().negate());

                        let jump_target = dis.get(&ins.memory_displacement64()).unwrap();
                        if jump_target.mnemonic() == Mnemonic::Ud2 {
                            constraints
                                .get_mut(addr)
                                .unwrap()
                                .sem_relationships
                                .push((jump_cond.negate(), "jump target is ud2".to_string()));
                        }
                    }
                    _ => {}
                }
            }
        }
        // debug!(
        //     "branch_cond_target_sources: {:#x?}",
        //     branch_cond_target_sources
        // );

        let mut inserted = false;

        for (addr, ins_ssa) in &ssa.ssa_map {
            // debug!("indirect_call matcher working on 0x{:x}", addr);
            let ins = dis.get(addr).unwrap();
            let ins_proof = proofs.get(addr).unwrap();
            let ins_cons = constraints.get_mut(addr).unwrap();

            let mut hint_assertions = vec![];
            for (policy_name, hint_rel) in &ins_proof.hints {
                match policy_name.as_str() {
                    "RIPConst" => {
                        // assert!(ins.memory_base().is_ip());
                        // assert!(ins.memory_base().size() == 8);
                        // let hint_rel = hint_rel.as_ref().unwrap();
                        // let mov_dst = location_operand(ins, 0)?;
                        // let dst_check = expr!(
                        //     expr_to_ssexpr(&GenericExpr::Var(mov_dst), &ins_ssa.ssa)?,
                        //     bv!("="),
                        //     hint_rel.left_hand_side.clone()
                        // );
                        // hint_assertions.push((
                        //     dst_check,
                        //     format!("destination check of RIPConst hint at 0x{:X}", addr),
                        // ));
                        // assert_ne!(dis.get(addr), None);

                        // let fnptr_addr = Const::new(
                        //     Sort::BitVec(64),
                        //     format!("fnptr_{:x}", dis.get(addr).unwrap().memory_displacement64()),
                        // );
                        // possible_fnptrs.insert(fnptr_addr.clone());
                        // ins_cons.constants.insert(fnptr_addr.clone());

                        // debug!(
                        //     "fnptr_assumption: {:x?} ------ {:x?}",
                        //     dis.get(addr),
                        //     ins.mnemonic()
                        // );

                        // let fnptr_assumption = expr!(
                        //     Imm::from(dis.get(addr).unwrap().memory_displacement64()).into(),
                        //     bv!("="),
                        //     fnptr_addr.clone().into()
                        // );
                        // ins_cons
                        //     .sem_relationships
                        //     .push((fnptr_assumption, "fnptr in mov/lea".to_string()));
                        // let fnptr_const = fnptr_addr.clone().into();
                        if ins.mnemonic() == Mnemonic::Mov {
                            inserted = true;
                            let mov_addr = match &ins_ssa.ss_asgns.iter().next().unwrap().rhs {
                                GenericExpr::Var(x) => {
                                    if let GenericLocation::Memory(m) = &x.loc {
                                        m.take_address()?
                                    } else {
                                        panic!("src of mov is not memory")
                                    }
                                }
                                _ => return Err(anyhow!("src of mov is not memory")),
                            };
                            call_targets.push(mov_addr.clone());
                        }

                        // let fnptr_rel = match ins.mnemonic() {
                        //     Mnemonic::Mov => {
                        //         let mov_addr = match &ins_ssa
                        //             .ss_asgns
                        //             .iter()
                        //             .next()
                        //             .unwrap()
                        //             .right_hand_side
                        //         {
                        //             GenericExpr::Var(x) => {
                        //                 if let GenericLocation::Memory(m) = &x.loc {
                        //                     m.take_address()?
                        //                 } else {
                        //                     panic!("src of mov is not memory")
                        //                 }
                        //             }
                        //             _ => return Err(anyhow!("src of mov is not memory")),
                        //         };
                        //         call_targets.push(mov_addr.clone());
                        //         inserted = true;
                        //         expr!(
                        //             expr_to_ssexpr(&fnptr_const, &ins_ssa.ssa)?,
                        //             bv!("="),
                        //             mov_addr.clone()
                        //         )
                        //     }
                        //     Mnemonic::Lea => {
                        //         expr!(
                        //             expr_to_ssexpr(&fnptr_const, &ins_ssa.ssa)?,
                        //             bv!("="),
                        //             hint_rel.left_hand_side.clone()
                        //         )
                        //     }
                        //     _ => panic!("Unreachable"),
                        // };
                        // ins_cons.prf_relationships.push(fnptr_rel);
                    }
                    "FuncPtrCalc" => {
                        let hint_rel = hint_rel.as_ref().unwrap();
                        if hint_rel.rhs != TABLE_IDX.clone().into()
                            && hint_rel.rhs != TYPED_TABLE_OFFSET.clone().into()
                        {
                            let mov_dst = location_operand(ins, 0)?;
                            let rhs_sort = hint_rel.lhs.infer_sort()?;
                            let dst_check = expr!(
                                expr_to_ssexpr(
                                    &mov_dst.get_sort().cast(rhs_sort)?(tease_expr(
                                        mov_dst.into(),
                                        None
                                    )?),
                                    &ins_ssa.ssa
                                )?,
                                bv!("="),
                                hint_rel.lhs.clone()
                            );
                            hint_assertions.push((
                                dst_check,
                                format!("destination check of FuncPtrCalc hint at 0x{:X}", addr),
                            ));
                        }

                        // debug!(
                        //     "At 0x{:x}, hint_rel right hand side: {:?}",
                        //     addr, hint_rel.right_hand_side
                        // );

                        if let GenericExpr::Const(ptr_calc_const) = hint_rel.rhs.clone() {
                            // if ptr_calc_const == *LUCET_BASE {
                            //     let lucet_base_rel = expr!(
                            //         hint_rel.left_hand_side.clone(),
                            //         bv!("="),
                            //         LUCET_BASE.clone().into()
                            //     );
                            //     debug!("sending rel into checker: {:?}", lucet_base_rel.clone());
                            //     ins_cons.prf_relationships.push(lucet_base_rel);
                            // } else
                            if ptr_calc_const == *TABLE_SIZE {
                                let (mov_addr, is_mem) =
                                    match &ins_ssa.ss_asgns.iter().next().unwrap().rhs {
                                        GenericExpr::Var(x) => {
                                            if let GenericLocation::Memory(m) = &x.loc {
                                                (m.take_address()?, true)
                                            } else if let GenericLocation::Register(r) = &x.loc {
                                                (
                                                    expr_to_ssexpr(
                                                        &GenericExpr::Var(Location::Register(
                                                            r.clone(),
                                                        )),
                                                        &ins_ssa.ssa,
                                                    )?,
                                                    false,
                                                )
                                            } else {
                                                panic!("src of mov is not memory")
                                            }
                                        }
                                        _ => return Err(anyhow!("src of mov is not memory")),
                                    };
                                let table_size_mem = expr!(
                                    LUCET_BASE.clone().into(),
                                    bv!("bvadd"),
                                    Imm::from(0x8 as i64).into()
                                );
                                let mut pres = vec![];
                                if is_mem {
                                    let src_check =
                                        expr!(mov_addr.clone(), bv!("="), table_size_mem.clone());
                                    pres.push(src_check);

                                    let read_mem: HashSet<_> = ins_ssa
                                        .read_locations
                                        .iter()
                                        .filter(|l| l.is_memory())
                                        .collect();
                                    assert!(read_mem.len() == 1);
                                    let read_mem = read_mem.into_iter().next().unwrap();
                                    let variant = expr!(
                                        ins_ssa.ssa.get_loc_ssa(read_mem).unwrap().into(),
                                        bv!("="),
                                        TABLE_SIZE.clone().into()
                                    );
                                    pres.push(variant);
                                } else {
                                    let src_check = expr!(
                                        mov_addr.clone(),
                                        bv!("="),
                                        TABLE_SIZE.clone().into()
                                    );
                                    pres.push(src_check);
                                }

                                ins_cons.prf_preconditions.push((
                                    vec![(
                                        unify_ssexprs(&pres, boolean!("or")),
                                        "Checking TableSize hint".to_string(),
                                    )],
                                    (
                                        expr!(hint_rel.lhs.clone(), bv!("="), hint_rel.rhs.clone()),
                                        "TableSize hint checked".to_string(),
                                    ),
                                ));
                            } else if ptr_calc_const
                                == Const::new(Sort::BitVec(64), format!("FnPtr"))
                            {
                                let mov_addr = match &ins_ssa.ss_asgns.iter().next().unwrap().rhs {
                                    GenericExpr::Var(x) => {
                                        if let GenericLocation::Memory(m) = &x.loc {
                                            m.take_address()?
                                        } else {
                                            panic!("src of mov is not memory")
                                        }
                                    }
                                    _ => return Err(anyhow!("src of mov is not memory")),
                                };

                                let lb_chk = expr!(
                                    mov_addr.clone(),
                                    bv!("bvult"),
                                    expr!(
                                        GUEST_BASE.clone().into(),
                                        bv!("bvadd"),
                                        expr!(
                                            TABLE_SIZE.clone().into(),
                                            bv!("bvmul"),
                                            Imm::from(0x10 as i64).into()
                                        )
                                    )
                                );
                                let ub_chk = expr!(
                                    mov_addr.clone(),
                                    bv!("bvugt"),
                                    GUEST_BASE.clone().into()
                                );
                                let mask_chk_1 = expr!(
                                    expr!(
                                        mov_addr.clone(),
                                        bv!("bvand"),
                                        Imm::from(0b111 as i64).into()
                                    ),
                                    bv!("="),
                                    Imm::from(0x0 as i64).into()
                                );
                                let mask_chk_2 = expr!(
                                    expr!(
                                        expr!(
                                            mov_addr.clone(),
                                            bv!("bvxor"),
                                            GUEST_BASE.clone().into()
                                        ),
                                        bv!("bvand"),
                                        Imm::from(0x8 as i64).into()
                                    ),
                                    bv!("="),
                                    Imm::from(0x8 as i64).into()
                                );

                                let mut pres = vec![];
                                // for offset in &typed_offsets {
                                //     let pre = expr!(
                                //         mov_addr.clone(),
                                //         bv!("="),
                                //         expr!(
                                //             expr!(
                                //                 GUEST_BASE.clone().into(),
                                //                 bv!("bvadd"),
                                //                 offset.clone().into()
                                //             ),
                                //             bv!("bvadd"),
                                //             Imm::from(0x8 as i64).into()
                                //         )
                                //     );
                                //     debug!("sending FnPtr addr into checker: {:?}", pre.clone());
                                //     pres.push(pre);
                                // }
                                pres.push(lb_chk);
                                pres.push(ub_chk);
                                pres.push(mask_chk_1);
                                pres.push(mask_chk_2);

                                let fn_ptr =
                                    Const::new(Sort::BitVec(64), format!("FnPtr_{:x}", addr));
                                ins_cons.prf_preconditions.push((
                                    vec![(
                                        unify_ssexprs(&pres, boolean!("and")),
                                        "checking FnType hint".to_string(),
                                    )],
                                    (
                                        expr!(
                                            hint_rel.lhs.clone(),
                                            bv!("="),
                                            fn_ptr.clone().into()
                                        ),
                                        "FnPtr hint checked".to_string(),
                                    ),
                                ));
                                ins_cons.constants.insert(fn_ptr.clone());
                                possible_fnptrs.insert(fn_ptr.clone());
                            }
                        }
                    }
                    _ => {}
                };
            }
            ins_cons.assertions.append(&mut hint_assertions);

            if ins.is_call_far_indirect() || ins.is_call_near_indirect() {
                if inserted {
                    inserted = false;
                } else {
                    log::debug!(
                        "indirect call found: {:?}",
                        ins_ssa.ss_asgns.clone().into_iter().next().unwrap()
                    );
                    let call_assignment = ins_ssa.ss_asgns.clone().into_iter().next().unwrap();
                    // TODO check LHS is rip
                    // if let GenericExpr::Var(v) = call_assignment.right_hand_side {
                    // debug!("call target: {:?}", &v);
                    // }
                    // let call_target = expr_to_ssexpr(
                    //     &expr_operand(ins, 0).unwrap(),
                    //     &ssa.ssa_map.get(addr).unwrap().ssa,
                    // )?;
                    call_targets.push(call_assignment.rhs);
                }
            }
        }

        for target in call_targets {
            let mut asserts = vec![];
            for fnptr in &possible_fnptrs {
                asserts.push(expr!(target.clone(), bv!("="), fnptr.clone().into()));
            }
            for addr in self.function_pointer_addresses.iter() {
                asserts.push(expr!(
                    target.clone(),
                    bv!("="),
                    Imm::from(*addr as u64).into()
                ));
            }
            for addr in self.function_addresses.iter() {
                asserts.push(expr!(
                    target.clone(),
                    bv!("="),
                    Imm::from(*addr.1 as u64).into()
                ));
            }
            let unified_assert = unify_ssexprs(&asserts, boolean!("or"));
            let guardian_cons = constraints.iter_mut().next_back().unwrap().1;
            guardian_cons.assertions.push((
                unified_assert,
                "checking indirect function call target".to_string(),
            ));
        }
        Ok(())
    }
}

pub struct MemAccessBounded {
    // These bases are all SSA formed expressions
    heap_base: SSExpr,
    stack_base: SSExpr,
    global_base_mem: SSExpr,
}

impl MemAccessBounded {
    pub fn new(ssa: &FuncSSA) -> Self {
        // find rdi.0
        let heap_base = SSExpr::from(ssa.get_heapbase().unwrap());
        MemAccessBounded {
            global_base_mem: expr!(
                heap_base.clone(),
                bv!("bvadd"),
                Imm::from(-0x8 as i64).into()
            ),
            heap_base,
            // TODO check calling convention for stack base, RBP or RSP?
            stack_base: SSExpr::from(ssa.get_stackbase().unwrap()),
        }
    }

    fn heap_assertions(
        &self,
        dst_addr: &GenericExpr<LocationSub>,
        addr: u64,
    ) -> Vec<AssertWithInfo> {
        let heap_lb = expr!(
            expr!(
                self.heap_base.clone(),
                bv!("bvsub"),
                Imm::from(0x1000 as u64).into()
            ),
            bv!("bvule"),
            dst_addr.clone().into()
        );
        let heap_ub = expr!(
            dst_addr.clone(),
            bv!("bvule"),
            expr!(
                self.heap_base.clone(),
                bv!("bvadd"),
                Imm::from(0x200000000 as u64).into()
            )
        );
        let mut result = vec![];
        result.push((heap_lb, format!("heap lower bound check at 0x{:X}", addr)));
        result.push((heap_ub, format!("heap upper bound check at 0x{:X}", addr)));
        result
    }

    fn stack_assertions(
        &self,
        dst_addr: &GenericExpr<LocationSub>,
        addr: u64,
        direction: Direction,
    ) -> Vec<AssertWithInfo> {
        let lb = match direction {
            Direction::READ => expr!(
                self.stack_base.clone(),
                bv!("bvadd"),
                Imm::from(0x2000 as u64).into()
            ),
            Direction::WRITE => self.stack_base.clone(),
        };
        let stack_lb = expr!(lb, bv!("bvuge"), dst_addr.clone());

        let stack_ub = expr!(
            dst_addr.clone(),
            bv!("bvuge"),
            expr!(
                self.stack_base.clone(),
                bv!("bvsub"),
                Imm::from(0x1000 as u64).into()
            )
        );
        let mut result = vec![];
        result.push((stack_lb, format!("stack lower bound check at 0x{:X}", addr)));
        result.push((stack_ub, format!("stack upper bound check at 0x{:X}", addr)));
        result
    }

    fn global_assertions(
        &self,
        dst_addr: &GenericExpr<LocationSub>,
        addr: u64,
    ) -> Vec<AssertWithInfo> {
        let global_base = SSExpr::Const(Const::new(Sort::BitVec(64), "GlobalBase".to_string()));
        let global_lb = expr!(global_base.clone(), bv!("bvule"), dst_addr.clone());
        let global_ub = expr!(
            dst_addr.clone(),
            bv!("bvule"),
            expr!(
                global_base.clone(),
                bv!("bvadd"),
                Imm::from(0x1000 as u64).into()
            )
        );

        let mut result = vec![];
        result.push((
            global_lb,
            format!("global lower bound check at 0x{:X}", addr),
        ));
        result.push((
            global_ub,
            format!("global upper bound check at 0x{:X}", addr),
        ));
        result
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
enum MemAccess {
    StackRead,
    StackWrite,
    HeapRead,
    HeapWrite,
    GlobalRead,
    GlobalWrite,
    JumpTableAccess,
    MetaAccess,
    RIPConst,
    // GlobalBase,
    // Unsupported,
}

enum Direction {
    READ,
    WRITE,
}

impl Matcher for MemAccessBounded {
    fn match_function(
        &self,
        ssa: &FuncSSA,
        dis: &Disassembled,
        proofs: &BTreeMap<u64, TotalProof>,
        constraints: &mut BTreeMap<u64, Constraints>,
        _cfi: &ControlFlowInfo,
    ) -> Result<()> {
        let global_base_const = Const::new(Sort::BitVec(64), "GlobalBase".to_string());
        let _first_entry = constraints
            .first_entry()
            .unwrap()
            .get_mut()
            .constants
            .insert(global_base_const.clone());
        let global_base = Expr::Const(Const::new(Sort::BitVec(64), "GlobalBase".to_string()));

        // declare HeapBase
        // assert(== HeapBase FirstRDI)
        // assert（== FirstRDI (bvadd RAX_10 0x200))

        // assert (== GlobalBase [HeapBase - 0x20])

        // < dst HeapBase
        // > dst HeapBase + 0x200000000

        let guardian_cons = constraints.iter_mut().next().unwrap().1;

        // put the guardians on disjoint regions.

        // TODO: It's interesting the stack does not need a lower bound guard,
        // we need to investigate on this.
        // stack guard is a lower bound guard, as stack grows down
        let stack_guard_ub = expr!(
            self.stack_base.clone(),
            bv!("bvult"),
            Imm::new(0x2000000000000000, ValSize::Size64).into()
        );
        let stack_guard_lb = expr!(
            self.stack_base.clone(),
            bv!("bvugt"),
            Imm::new(0x1000000000000000, ValSize::Size64).into()
        );
        guardian_cons
            .sem_relationships
            .push((stack_guard_ub, format!("stack upper bound guard")));
        guardian_cons
            .sem_relationships
            .push((stack_guard_lb, format!("stack lower bound guard")));

        // guarding heap boundaries on both ends
        let heap_guard_ub = expr!(
            self.heap_base.clone(),
            bv!("bvult"),
            Imm::new(0x4000000000000000, ValSize::Size64).into()
        );
        let heap_guard_lb = expr!(
            self.heap_base.clone(),
            bv!("bvugt"),
            Imm::new(0x3000000000000000, ValSize::Size64).into()
        );
        guardian_cons
            .sem_relationships
            .push((heap_guard_ub, format!("heap upper bound guard")));
        guardian_cons
            .sem_relationships
            .push((heap_guard_lb, format!("heap lower bound guard")));

        // guarding global boundaries on both ends
        let global_guard_ub = expr!(
            expr_to_ssexpr(&global_base, &ssa.init_ssa)?,
            bv!("bvult"),
            Imm::new(0x6000000000000000, ValSize::Size64).into()
        );
        let global_guard_lb = expr!(
            expr_to_ssexpr(&global_base, &ssa.init_ssa)?,
            bv!("bvugt"),
            Imm::new(0x5000000000000000, ValSize::Size64).into()
        );
        guardian_cons
            .sem_relationships
            .push((global_guard_ub, format!("global upper bound guard")));
        guardian_cons
            .sem_relationships
            .push((global_guard_lb, format!("global lower bound guard")));

        for (addr, ins_ssa) in &ssa.ssa_map {
            let ins = dis.get(addr).unwrap();
            let mut write_dests: Vec<_> = ins_ssa
                .written_locations
                .clone()
                .into_iter()
                .filter(|x| x.is_memory())
                .collect();
            assert!(write_dests.len() <= 1);
            let mut read_srcs: Vec<_> = ins_ssa
                .read_locations
                .clone()
                .into_iter()
                .filter(|x| x.is_memory())
                .collect();
            assert!(read_srcs.len() <= 1);

            let ssa_mem_written_destination_addr = match write_dests.pop() {
                Some(GenericLocation::Memory(x)) => Some(x.take_address()?),
                _ => None,
            };

            let ssa_mem_read_source_addr = match read_srcs.pop() {
                Some(GenericLocation::Memory(x)) => Some(x.take_address()?),
                _ => None,
            };

            let ins_proof = proofs.get(addr).unwrap();
            let ins_cons = constraints.get_mut(addr).unwrap();

            // deal with hints and determine the access category
            let mut access_categories = HashSet::new();
            for (policy_name, hint_rel) in &ins_proof.hints {
                match policy_name.as_str() {
                    "StackRead" => {
                        access_categories.insert(MemAccess::StackRead);
                    }
                    "StackWrite" => {
                        access_categories.insert(MemAccess::StackWrite);
                    }
                    "HeapRead" => {
                        access_categories.insert(MemAccess::HeapRead);
                    }
                    "HeapWrite" => {
                        access_categories.insert(MemAccess::HeapWrite);
                    }
                    "MetaAccess" => {
                        access_categories.insert(MemAccess::MetaAccess);
                    }
                    "JumpTableAccess" => {
                        access_categories.insert(MemAccess::JumpTableAccess);
                    }
                    "GlobalRead" => {
                        access_categories.insert(MemAccess::GlobalRead);
                    }
                    "GlobalWrite" => {
                        access_categories.insert(MemAccess::GlobalWrite);
                    }
                    "GlobalBaseLookup" => {
                        let hint_rel = hint_rel.as_ref().unwrap();
                        // check that the RHS of the hint is GlobalBase const
                        assert!(hint_rel.rhs == expr_to_ssexpr(&global_base, &ins_ssa.ssa)?);
                        assert!(ins.mnemonic() == Mnemonic::Mov);
                        // ignoring the continuations here
                        let mov_dst = location_operand(ins, 0)?;
                        let dst_check = expr!(
                            expr_to_ssexpr(&GenericExpr::Var(mov_dst), &ins_ssa.ssa)?,
                            bv!("="),
                            hint_rel.lhs.clone()
                        );
                        let mov_addr = match &ins_ssa.ss_asgns.iter().next().unwrap().rhs {
                            GenericExpr::Var(x) => {
                                if let GenericLocation::Memory(m) = &x.loc {
                                    m.take_address()?
                                } else {
                                    panic!("src of mov is not memory")
                                }
                            }
                            _ => return Err(anyhow!("src of mov is not memory")),
                        };

                        let src_check = expr!(mov_addr, bv!("bvule"), self.global_base_mem.clone());
                        let mut hint_assertions = vec![];
                        hint_assertions.push((
                            dst_check,
                            format!("destination check of GlobalBase hint at 0x{:X}", addr),
                        ));
                        hint_assertions.push((
                            src_check,
                            format!("source check of GlobalBase hint at 0x{:X}", addr),
                        ));

                        ins_cons.prf_preconditions.push((
                            hint_assertions,
                            (
                                expr!(hint_rel.lhs.clone(), bv!("="), hint_rel.rhs.clone()),
                                "GlobalBaseLookup hint checked".to_string(),
                            ),
                        ));
                    }
                    "RIPConst" => {
                        access_categories.insert(MemAccess::RIPConst);
                    }
                    _ => {}
                };
            }

            if ssa_mem_written_destination_addr.is_none()
                && ssa_mem_read_source_addr.is_none()
                && access_categories.is_empty()
            {
                continue; // no memory access
            }

            assert!(
                access_categories.len() == 1,
                "Not exactly one access category hinted at address 0x{:x}, {:?}",
                addr,
                access_categories
            );

            let access_category = access_categories.iter().next().unwrap();

            let mut assertions = match access_category {
                // FIXME [!!!!!!IMPORTANT!!!!!!]
                // TODO: Two things need to be addressed here:
                // 1. Read is allowed 8KB above the base pointer -> arg for direction.
                // 2. Probestack must also be handled to expand the lower bound ->
                // more proofs for probestack. Unfortunately, we haven't seen any case yet.
                MemAccess::StackRead => self.stack_assertions(
                    &ssa_mem_read_source_addr.unwrap(),
                    *addr,
                    Direction::READ,
                ),
                MemAccess::StackWrite => self.stack_assertions(
                    &ssa_mem_written_destination_addr.unwrap(),
                    *addr,
                    Direction::WRITE,
                ),
                MemAccess::HeapRead => {
                    self.heap_assertions(&ssa_mem_read_source_addr.unwrap(), *addr)
                }
                MemAccess::HeapWrite => {
                    self.heap_assertions(&ssa_mem_written_destination_addr.unwrap(), *addr)
                }
                MemAccess::GlobalRead => {
                    self.global_assertions(&ssa_mem_read_source_addr.unwrap(), *addr)
                }
                MemAccess::GlobalWrite => {
                    self.global_assertions(&ssa_mem_written_destination_addr.unwrap(), *addr)
                }
                MemAccess::MetaAccess | MemAccess::JumpTableAccess => {
                    continue;
                }
                MemAccess::RIPConst => continue,
            };

            ins_cons.assertions.append(&mut assertions);
        }
        Ok(())
    }
}
