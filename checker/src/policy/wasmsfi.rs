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
        let jmp_dummy = Const::new(Sort::BitVec(64), format!("jmp_tar_dummy"));
        dummy_guard.constants.insert(jmp_dummy.clone());
        let mut _possible_jmp_tar: HashSet<Const> = vec![jmp_dummy.clone()].into_iter().collect();

        let mut bcts: BTreeMap<u64, BTreeMap<u64, SSExpr>> = BTreeMap::new();
        for (addr, ins_ssa) in &ssa.ssa_map {
            let ins = dis.get(addr).unwrap();
            if ins_ssa.ss_asgns.len() != 1 {
                continue;
            }
            match ins.mnemonic() {
                Mnemonic::Jae
                | Mnemonic::Ja
                | Mnemonic::Jb
                | Mnemonic::Jbe
                | Mnemonic::Je
                | Mnemonic::Jne => {
                    let jc: SSExpr = self.resolve_flags(ins, ins_ssa)?;
                    bcts.entry(ins.memory_displacement64())
                        .or_insert(BTreeMap::new())
                        .insert(*addr, jc.clone());
                    bcts.entry(ins.next_ip())
                        .or_insert(BTreeMap::new())
                        .insert(*addr, jc.clone().negate());
                }
                _ => {}
            }
        }

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
                                    hint_assertions.push((dst_check, ""));
                                }
                            }

                            match name {
                                "JmpIdx" => {
                                    let bound = u64::from_str_radix(&number, 16)?;
                                    if bound == 0 {
                                        continue;
                                    }

                                    let bb_head = find_site_bb(&_cfi.basic_blocks, *addr)?;
                                    let conds = bcts.get(&bb_head).unwrap();
                                    for c in conds {
                                        ins_cons.branch_conditions.push(c.1.clone());
                                    }
                                    let bi = Imm::from(bound).into();
                                    let hrt = expr!(hint_rel.lhs.clone(), bv!("bvult"), bi);
                                    let check = vec![(hrt, "Checking JmpIdx hint".to_string())];
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
                let jtc = Const::new(Sort::BitVec(64), format!("JmpTarget_{:x}", ins.next_ip()));
                let assertion = expr!(jump_target.clone(), bv!("="), jtc.into());
                let gc = constraints.iter_mut().next_back().unwrap().1;
                gc.assertions.push((assertion, "ind-jmp".to_string()));
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
    static ref TYPED_OFFSET: Const = Const::new(Sort::BitVec(64), "TypedTableOffset".to_string());
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
        let dg = constraints.iter_mut().next().unwrap().1;
        dg.constants.insert(LUCET_BASE.clone());
        dg.constants.insert(GUEST_BASE.clone());
        dg.constants.insert(TABLE_SIZE.clone());
        let lti = Imm::from(self.lucet_tables).into();
        let lt = expr!(LUCET_BASE.clone().into(), bv!("="), lti);
        dg.sem_relationships.push((lt, "lucet_base".to_string()));
        let gti = Imm::from(self.guest_table_0).into();
        let gt = expr!(GUEST_BASE.clone().into(), bv!("="), gti);
        dg.sem_relationships.push((gt, "guest_base".to_string()));
        let gtsi = Imm::from(self.guest_table_0_size).into();
        let ts = expr!(TABLE_SIZE.clone().into(), bv!("="), gtsi);
        dg.sem_relationships.push((ts, "table_size".to_string()));

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

        let mut inserted = false;

        for (addr, ins_ssa) in &ssa.ssa_map {
            let ins = dis.get(addr).unwrap();
            let ins_proof = proofs.get(addr).unwrap();
            let ins_cons = constraints.get_mut(addr).unwrap();

            let mut hint_assertions = vec![];
            for (policy_name, hint_rel) in &ins_proof.hints {
                match policy_name.as_str() {
                    "RIPConst" => {
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
                    }
                    "FuncPtrCalc" => {
                        let hr = hint_rel.as_ref().unwrap();
                        if hr.rhs != TABLE_IDX.clone().into()
                            && hr.rhs != TYPED_OFFSET.clone().into()
                        {
                            let mov_dst = location_operand(ins, 0)?;
                            let rhs_sort = hr.lhs.infer_sort()?;
                            let te = tease_expr(mov_dst.into(), None)?;
                            let md = &mov_dst.get_sort().cast(rhs_sort)?(te);
                            let dct = expr_to_ssexpr(md, &ins_ssa.ssa)?;
                            let dst_check = expr!(dct, bv!("="), hr.lhs.clone());
                            hint_assertions.push((dst_check, format!("dst fpc 0x{:X}", addr)));
                        }

                        if let GenericExpr::Const(pc) = hr.rhs.clone() {
                            if pc == *TABLE_SIZE {
                                let (ma, is_mem) =
                                    match &ins_ssa.ss_asgns.iter().next().unwrap().rhs {
                                        GenericExpr::Var(x) => {
                                            if let GenericLocation::Memory(m) = &x.loc {
                                                (m.take_address()?, true)
                                            } else if let GenericLocation::Register(r) = &x.loc {
                                                let t = &GenericExpr::Var(Location::Register(
                                                    r.clone(),
                                                ));
                                                (expr_to_ssexpr(t, &ins_ssa.ssa)?, false)
                                            } else {
                                                panic!("src of mov is not memory")
                                            }
                                        }
                                        _ => return Err(anyhow!("src of mov is not memory")),
                                    };
                                let be = Imm::from(0x8 as i64).into();
                                let tsm = expr!(LUCET_BASE.clone().into(), bv!("bvadd"), be);
                                let mut pres = vec![];
                                let ts = TABLE_SIZE.clone().into();
                                if is_mem {
                                    let src_check = expr!(ma.clone(), bv!("="), tsm.clone());
                                    pres.push(src_check);

                                    let read_mem: HashSet<_> = ins_ssa
                                        .read_locations
                                        .iter()
                                        .filter(|l| l.is_memory())
                                        .collect();
                                    let rm = read_mem.into_iter().next().unwrap();
                                    let rmu = ins_ssa.ssa.get_loc_ssa(rm).unwrap().into();
                                    let variant = expr!(rmu, bv!("="), ts);
                                    pres.push(variant);
                                } else {
                                    pres.push(expr!(ma.clone(), bv!("="), ts));
                                }

                                let hre = expr!(hr.lhs.clone(), bv!("="), hr.rhs.clone());
                                ins_cons.prf_preconditions.push((
                                    vec![(unify_ssexprs(&pres, boolean!("or")), "".to_string())],
                                    (hre, "TableSize hint checked".to_string()),
                                ));
                            } else if pc == Const::new(Sort::BitVec(64), format!("FnPtr")) {
                                let m = match &ins_ssa.ss_asgns.iter().next().unwrap().rhs {
                                    GenericExpr::Var(x) => {
                                        if let GenericLocation::Memory(m) = &x.loc {
                                            m.take_address()?
                                        } else {
                                            panic!("src of mov is not memory")
                                        }
                                    }
                                    _ => return Err(anyhow!("src of mov is not memory")),
                                };
                                let bt = Imm::from(0x10 as i64).into();
                                let t = expr!(TABLE_SIZE.clone().into(), bv!("bvmul"), bt);
                                let k = expr!(GUEST_BASE.clone().into(), bv!("bvadd"), t);
                                let lb_chk = expr!(m.clone(), bv!("bvult"), k);
                                let ub_chk =
                                    expr!(m.clone(), bv!("bvugt"), GUEST_BASE.clone().into());
                                let booo =
                                    expr!(m.clone(), bv!("bvand"), Imm::from(0b111 as i64).into());
                                let mask_chk_1 =
                                    expr!(booo, bv!("="), Imm::from(0x0 as i64).into());
                                let e = Imm::from(0x8 as i64).into();
                                let e2 = Imm::from(0x8 as i64).into();
                                let ma = expr!(m.clone(), bv!("bvxor"), GUEST_BASE.clone().into());
                                let mask_chk_2 = expr!(expr!(ma, bv!("bvand"), e), bv!("="), e2);

                                let mut pres = vec![];
                                pres.push(lb_chk);
                                pres.push(ub_chk);
                                pres.push(mask_chk_1);
                                pres.push(mask_chk_2);

                                let fn_ptr =
                                    Const::new(Sort::BitVec(64), format!("FnPtr_{:x}", addr));
                                let fh = expr!(hr.lhs.clone(), bv!("="), fn_ptr.clone().into());
                                ins_cons.prf_preconditions.push((
                                    vec![(unify_ssexprs(&pres, boolean!("and")), "".to_string())],
                                    (fh, "FnPtr hint checked".to_string()),
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
                    let call_assignment = ins_ssa.ss_asgns.clone().into_iter().next().unwrap();
                    call_targets.push(call_assignment.rhs);
                }
            }
        }

        for t in call_targets {
            let mut asserts = vec![];
            for fnptr in &possible_fnptrs {
                asserts.push(expr!(t.clone(), bv!("="), fnptr.clone().into()));
            }
            for addr in self.function_pointer_addresses.iter() {
                asserts.push(expr!(t.clone(), bv!("="), Imm::from(*addr as u64).into()));
            }
            for addr in self.function_addresses.iter() {
                asserts.push(expr!(t.clone(), bv!("="), Imm::from(*addr.1 as u64).into()));
            }
            let unified_assert = unify_ssexprs(&asserts, boolean!("or"));
            let gc = constraints.iter_mut().next_back().unwrap().1;
            gc.assertions.push((unified_assert, "indcall".to_string()));
        }
        Ok(())
    }
}

pub struct MemAccessBounded {
    heap_base: SSExpr,
    stack_base: SSExpr,
    global_base_mem: SSExpr,
}

impl MemAccessBounded {
    pub fn new(ssa: &FuncSSA) -> Self {
        // find rdi.0
        let heap_base = SSExpr::from(ssa.get_heapbase().unwrap());
        let ne = Imm::from(-0x8 as i64).into();
        let global_base_mem = expr!(heap_base.clone(), bv!("bvadd"), ne);
        let stack_base = SSExpr::from(ssa.get_stackbase().unwrap());
        MemAccessBounded {
            heap_base,
            stack_base,
            global_base_mem,
        }
    }

    fn heap(&self, da: &GenericExpr<LocationSub>, addr: u64) -> Vec<AssertWithInfo> {
        let ot = Imm::from(0x1000 as u64).into();
        let hlt = expr!(self.heap_base.clone(), bv!("bvsub"), ot);
        let heap_lb = expr!(hlt, bv!("bvule"), da.clone().into());
        let tm = Imm::from(0x200000000 as u64).into();
        let hut = expr!(self.heap_base.clone(), bv!("bvadd"), tm);
        let heap_ub = expr!(da.clone(), bv!("bvule"), hut);
        let mut result = vec![];
        result.push((heap_lb, format!("heap lower bound check at 0x{:X}", addr)));
        result.push((heap_ub, format!("heap upper bound check at 0x{:X}", addr)));
        result
    }

    fn stack(&self, da: &GenericExpr<LocationSub>, a: u64, d: Direction) -> Vec<AssertWithInfo> {
        let tt = Imm::from(0x2000 as u64).into();
        let lb = match d {
            Direction::READ => expr!(self.stack_base.clone(), bv!("bvadd"), tt),
            Direction::WRITE => self.stack_base.clone(),
        };
        let stack_lb = expr!(lb, bv!("bvuge"), da.clone());
        let ot = Imm::from(0x1000 as u64).into();
        let sut = expr!(self.stack_base.clone(), bv!("bvsub"), ot);
        let stack_ub = expr!(da.clone(), bv!("bvuge"), sut);
        let mut result = vec![];
        result.push((stack_lb, format!("stack lower bound check at 0x{:X}", a)));
        result.push((stack_ub, format!("stack upper bound check at 0x{:X}", a)));
        result
    }

    fn global(&self, da: &GenericExpr<LocationSub>, addr: u64) -> Vec<AssertWithInfo> {
        let gb = SSExpr::Const(Const::new(Sort::BitVec(64), "GlobalBase".to_string()));
        let global_lb = expr!(gb.clone(), bv!("bvule"), da.clone());
        let ot = Imm::from(0x1000 as u64).into();
        let gut = expr!(gb.clone(), bv!("bvadd"), ot);
        let gu = expr!(da.clone(), bv!("bvule"), gut);
        let mut result = vec![];
        result.push((global_lb, format!("global lower 0x{:X}", addr)));
        result.push((gu, format!("global upper 0x{:X}", addr)));
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
        let gb = Expr::Const(Const::new(Sort::BitVec(64), "GlobalBase".to_string()));
        let gc = constraints.iter_mut().next().unwrap().1;

        let sguc = Imm::new(0x2000000000000000, ValSize::Size64).into();
        let sglc = Imm::new(0x1000000000000000, ValSize::Size64).into();
        let sgu = expr!(self.stack_base.clone(), bv!("bvult"), sguc);
        let sgl = expr!(self.stack_base.clone(), bv!("bvugt"), sglc);
        gc.sem_relationships.push((sgu, format!("stack upper")));
        gc.sem_relationships.push((sgl, format!("stack lower")));

        let hguc = Imm::new(0x4000000000000000, ValSize::Size64).into();
        let hglc = Imm::new(0x3000000000000000, ValSize::Size64).into();
        let hgu = expr!(self.heap_base.clone(), bv!("bvult"), hguc);
        let hgl = expr!(self.heap_base.clone(), bv!("bvugt"), hglc);
        gc.sem_relationships.push((hgu, format!("heap upper")));
        gc.sem_relationships.push((hgl, format!("heap lower")));

        let gguc = Imm::new(0x6000000000000000, ValSize::Size64).into();
        let gglc = Imm::new(0x5000000000000000, ValSize::Size64).into();
        let ggu = expr!(expr_to_ssexpr(&gb, &ssa.init_ssa)?, bv!("bvult"), gguc);
        let ggl = expr!(expr_to_ssexpr(&gb, &ssa.init_ssa)?, bv!("bvugt"), gglc);
        gc.sem_relationships.push((ggu, format!("global upper")));
        gc.sem_relationships.push((ggl, format!("global lower")));

        for (addr, ins_ssa) in &ssa.ssa_map {
            let ins = dis.get(addr).unwrap();
            let wd = ins_ssa.written_locations.clone();
            let mut write_dests: Vec<_> = wd.into_iter().filter(|x| x.is_memory()).collect();
            let rs = ins_ssa.read_locations.clone();
            let mut read_srcs: Vec<_> = rs.into_iter().filter(|x| x.is_memory()).collect();

            let dst_a = match write_dests.pop() {
                Some(GenericLocation::Memory(x)) => Some(x.take_address()?),
                _ => None,
            };
            let src_a = match read_srcs.pop() {
                Some(GenericLocation::Memory(x)) => Some(x.take_address()?),
                _ => None,
            };

            let ins_proof = proofs.get(addr).unwrap();
            let ins_cons = constraints.get_mut(addr).unwrap();

            // deal with hints and determine the access category
            let mut cat = HashSet::new();
            for (policy_name, hint_rel) in &ins_proof.hints {
                match policy_name.as_str() {
                    "StackRead" => cat.insert(MemAccess::StackRead),
                    "StackWrite" => cat.insert(MemAccess::StackWrite),
                    "HeapRead" => cat.insert(MemAccess::HeapRead),
                    "HeapWrite" => cat.insert(MemAccess::HeapWrite),
                    "MetaAccess" => cat.insert(MemAccess::MetaAccess),
                    "JumpTableAccess" => cat.insert(MemAccess::JumpTableAccess),
                    "GlobalRead" => cat.insert(MemAccess::GlobalRead),
                    "GlobalWrite" => cat.insert(MemAccess::GlobalWrite),
                    "GlobalBaseLookup" => {
                        let hint_rel = hint_rel.as_ref().unwrap();
                        let mov_dst = location_operand(ins, 0)?;
                        let dst_ssexpr = expr_to_ssexpr(&GenericExpr::Var(mov_dst), &ins_ssa.ssa)?;
                        let dst_check = expr!(dst_ssexpr, bv!("="), hint_rel.lhs.clone());
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
                        let mut h = vec![];
                        h.push((dst_check, format!("dst of GlobalBase at 0x{:X}", addr)));
                        h.push((src_check, format!("src of GlobalBase  at 0x{:X}", addr)));

                        let hr = expr!(hint_rel.lhs.clone(), bv!("="), hint_rel.rhs.clone());
                        ins_cons.prf_preconditions.push((h, (hr, "".to_string())));
                        true
                    }
                    "RIPConst" => cat.insert(MemAccess::RIPConst),
                    _ => true,
                };
            }

            if dst_a.is_none() && src_a.is_none() && cat.is_empty() {
                continue; // no memory access
            }

            assert!(cat.len() == 1, "Not one-cate at 0x{:x}, {:?}", addr, cat);

            let access_category = cat.iter().next().unwrap();

            let mut assertions = match access_category {
                MemAccess::StackRead => self.stack(&src_a.unwrap(), *addr, Direction::READ),
                MemAccess::StackWrite => self.stack(&dst_a.unwrap(), *addr, Direction::WRITE),
                MemAccess::HeapRead => self.heap(&src_a.unwrap(), *addr),
                MemAccess::HeapWrite => self.heap(&dst_a.unwrap(), *addr),
                MemAccess::GlobalRead => self.global(&src_a.unwrap(), *addr),
                MemAccess::GlobalWrite => self.global(&dst_a.unwrap(), *addr),
                MemAccess::MetaAccess | MemAccess::JumpTableAccess | MemAccess::RIPConst => {
                    continue;
                }
            };

            ins_cons.assertions.append(&mut assertions);
        }
        Ok(())
    }
}
