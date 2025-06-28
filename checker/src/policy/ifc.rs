use super::Matcher;
use crate::dis::{ControlFlowInfo, Disassembled};
use crate::policy::Constraints;
use crate::ssa::*;
use crate::validate::*;
use anyhow::Result;
use iced_asm::{Mnemonic, Register};
use ir::*;
use lazy_static::lazy_static;
use smt::{StringifyExpr, StringifySym};
use std::collections::BTreeMap;
use std::vec;

lazy_static! {
    static ref F: Const = Const::new(Sort::Bool, "false".to_string());
    static ref T: Const = Const::new(Sort::Bool, "true".to_string());
}

const TAINT_REGS: [Option<Register>; 8] = [
    None,
    Some(Register::RAX),
    Some(Register::RDI),
    Some(Register::RSI),
    Some(Register::RDX),
    Some(Register::RCX),
    Some(Register::R8),
    Some(Register::R9),
];

pub struct IFCSafe {}

impl IFCSafe {
    pub fn new() -> Self {
        IFCSafe {}
    }

    fn extract_labels(&self, ssa_loc: LocationSub) -> String {
        match ssa_loc.loc {
            GenericLocation::Register(_) => {
                let expr = GenericExpr::Var(ssa_loc.clone());
                format!("{}.LABEL", expr.stringify_expr().unwrap()).to_string()
            }
            GenericLocation::Memory(_) => format!("mem_{}.LABEL", ssa_loc.sub).to_string(),
            _ => unreachable!("other location type should not be used in IFC"),
        }
    }

    fn extract_labels_expr(&self, expr: GenericExpr<LocationSub>) -> (Vec<String>, Vec<String>) {
        let mut labels: Vec<String> = vec![];
        let mut secmem: Vec<String> = vec![];

        match expr.clone() {
            GenericExpr::Unary(_, r) => {
                let mut res = self.extract_labels_expr(*r);
                labels.append(res.0.as_mut());
                secmem.append(res.1.as_mut());
            }
            GenericExpr::Binary(_, l, r) => {
                let mut res1 = self.extract_labels_expr(*l);
                let mut res2 = self.extract_labels_expr(*r);
                labels.append(res1.0.as_mut());
                labels.append(res2.0.as_mut());
                secmem.append(res1.1.as_mut());
                secmem.append(res2.1.as_mut());
            }
            GenericExpr::Var(v) => {
                labels.push(self.extract_labels(v));
                match v.loc {
                    GenericLocation::Memory(x) => {
                        if x.segment_reg.register() == Register::GS {
                            secmem.push(self.extract_labels(v));
                        }
                    }
                    _ => {}
                }
            }
            GenericExpr::Imm(_) => labels.push("false".to_string()),
            _ => unimplemented!("EXPR: {:?}", expr.stringify_expr().unwrap()),
        }
        (labels, secmem)
    }

    fn find_def_reaching_ret(
        &self,
        reg: &Register,
        ssa: &FuncSSA,
        dis: &Disassembled,
        cfi: &ControlFlowInfo,
    ) -> Vec<Option<LocationSub>> {
        let mut ret_defs = vec![];
        // get all bbs that have return instructions from cfi
        for (_, range) in cfi.basic_blocks.iter() {
            let ins = dis.get(&range.end).unwrap();
            if ins.mnemonic() == Mnemonic::Ret {
                let ssa_state = ssa.ssa_map.get(&range.end).unwrap().ssa.clone();
                let gen_reg = GenericLocation::Register(reg.clone());
                let ssa_reg = ssa_state.convert_to_ss(&gen_reg);
                let loc_ssa = ssa_state.get_loc_ssa(&ssa_reg);
                ret_defs.push(loc_ssa);
            }
        }

        ret_defs
    }

    fn magic_sequence_handling(
        &self,
        mut bits: i64,
        ssa: &FuncSSA,
        dis: &BTreeMap<u64, iced_asm::Instruction>,
        cfi: &ControlFlowInfo,
        cons: &mut BTreeMap<u64, Constraints>,
        start: &u64,
    ) {
        // for 1 to 8
        for i in (0..TAINT_REGS.len()).rev() {
            let var_name = bits.clone() & 1;
            let taint = var_name;
            bits = bits >> 1;
            let reg = TAINT_REGS[i];
            if reg.is_none() {
                continue;
            }
            let truth_val = match taint {
                0 => F.clone(),
                1 => T.clone(),
                _ => unreachable!(),
            };
            if i == 1 && taint == 0 {
                for def in self.find_def_reaching_ret(&Register::RAX, ssa, dis, cfi) {
                    if def.is_none() {
                        continue;
                    }
                    let ssdef = SSExpr::from(def.unwrap());
                    let label = ssdef.stringify_expr().unwrap() + ".LABEL";
                    let label_const = Const::new(Sort::Bool, label).into();
                    let label_expr = expr!(label_const, boolean!("="), F.clone().into());
                    let check = (label_expr, format!("return taint check for {:?} ", reg));
                    cons.get_mut(&start).unwrap().sem_relationships.push(check);
                }
                continue;
            }
            let check = fun_name(ssa, reg, truth_val);
            cons.get_mut(&start).unwrap().sem_relationships.push(check);
        }
    }
}

impl Matcher for IFCSafe {
    fn match_function(
        &self,
        ssa: &FuncSSA,
        dis: &Disassembled,
        proofs: &BTreeMap<u64, TotalProof>,
        cons: &mut BTreeMap<u64, Constraints>,
        cfi: &ControlFlowInfo,
    ) -> Result<()> {
        // handling magic sequence
        let start = dis.first_key_value().unwrap().0;
        let hints = proofs.get(&(start - 0x10)).unwrap().hints.clone();
        let magic = hints.into_iter().next().unwrap().0;
        let bits = i64::from_str_radix(&magic[8..10], 16).unwrap();
        self.magic_sequence_handling(bits, ssa, dis, cfi, cons, start);

        let mut sinks = vec![];

        for (addr, ins_ssa) in &ssa.ssa_map {
            let ins = dis.get(addr).unwrap();
            let mut sem_rel = vec![];
            let mut asserts = vec![];

            if ins.mnemonic() == Mnemonic::Call {
                assert_ne!(cfi.bb_of_ins(*addr).unwrap().0, *addr);
                let prev_ins_addr = dis.keys().rev().skip_while(|&x| x >= addr).next().unwrap();
                let f_addr = ins.memory_displacement64();
                let tmp = proofs.get(&(f_addr - 0x10));
                if tmp.is_none() || tmp.unwrap().hints.len() == 0 {
                    continue;
                }
                let call_magic = proofs.get(&(f_addr - 0x10)).unwrap().hints.clone();
                let mut bits =
                    i64::from_str_radix(&call_magic.into_iter().next().unwrap().0[8..10], 16)
                        .unwrap();

                for i in (0..TAINT_REGS.len()).rev() {
                    let var_name = bits.clone() & 1;
                    let taint = var_name;
                    bits = bits >> 1;
                    let reg = TAINT_REGS[i];
                    if reg.is_none() {
                        continue;
                    }
                    let truth_val = match taint {
                        0 => F.clone(),
                        1 => T.clone(),
                        _ => unreachable!(),
                    };
                    let ssa_state = if i == 1 {
                        ssa.ssa_map.get(&addr).unwrap().ssa.clone()
                    } else {
                        ssa.ssa_map.get(&prev_ins_addr).unwrap().ssa.clone()
                    };
                    if i != 1 && taint == 1 {
                        continue;
                    }
                    let gen_reg = GenericLocation::Register(reg.clone().unwrap());
                    let ssa_reg = ssa_state.convert_to_ss(&gen_reg);
                    let loc_ssa = ssa_state.get_loc_ssa(&ssa_reg);
                    let ssdef = SSExpr::from(loc_ssa.unwrap());
                    let reg_label = ssdef.stringify_expr().unwrap() + ".LABEL";
                    let label_const = Const::new(Sort::Bool, reg_label).into();
                    let expr = expr!(label_const, boolean!("="), truth_val.into());
                    let check = (expr, format!("taint check for {:?} at return", reg));
                    cons.get_mut(&start).unwrap().sem_relationships.push(check);
                }
            }
            for assign in ins_ssa.ss_asgns.iter() {
                let lhs = assign.lhs;
                let rhs = assign.rhs.clone();
                match lhs.loc {
                    GenericLocation::Register(r) => match r.register() {
                        Register::RIP => continue,
                        Register::RDI
                        | Register::RSI
                        | Register::RDX
                        | Register::RCX
                        | Register::R8
                        | Register::R9 => {}
                        _ => sinks.push(lhs.stringify_sym().unwrap() + ".LABEL"),
                    },
                    GenericLocation::Flag(_) | GenericLocation::MAS(_) => continue,
                    _ => {}
                }
                match rhs {
                    GenericExpr::Any(_) => continue,
                    _ => {}
                }

                let lhs_label = self.extract_labels(lhs);
                let rhs_label = self.extract_labels_expr(rhs);
                for label in rhs_label.0.iter() {
                    // label does not start with rdi or rsi or rdx or rcx or r8 or r9
                    if !(label.starts_with("rdi")
                        || label.starts_with("rsi")
                        || label.starts_with("rdx")
                        || label.starts_with("rcx")
                        || label.starts_with("r8")
                        || label.starts_with("r9"))
                        && !label.starts_with("mem_")
                        && !sinks.contains(label)
                    {
                        let r = Const::new(Sort::Bool, label.to_string()).into();
                        let pub_cons = expr!(F.clone().into(), boolean!("="), r);
                        sem_rel.push((pub_cons, format!("nonsink {:X}", addr)));
                    }

                    let d = if Const::new(Sort::Bool, label.to_string()) == F.clone() {
                        boolean!("=>")
                    } else {
                        boolean!("=")
                    };
                    let l = Const::new(Sort::Bool, label.to_string()).into();
                    let r = Const::new(Sort::Bool, lhs_label.clone()).into();
                    let assign_cons = expr!(l, d, r);
                    sem_rel.push((assign_cons, format!("assignment relation  at 0x{:X}", addr)));
                }

                for label in rhs_label.1.iter() {
                    let l = Const::new(Sort::Bool, label.to_string()).into();
                    let sec_cons = expr!(l, boolean!("="), T.clone().into());
                    sem_rel.push((sec_cons, format!("secret read check at 0x{:X}", addr)));
                }
            }

            let wt = ins_ssa.written_locations.clone();
            let write_dsts: Vec<_> = wt.into_iter().filter(|x| x.is_memory()).collect();
            assert!(write_dsts.len() <= 1);
            let rs = ins_ssa.read_locations.clone();
            let read_srcs: Vec<_> = rs.into_iter().filter(|x| x.is_memory()).collect();
            assert!(read_srcs.len() <= 1);

            write_dsts.iter().for_each(|dst| match dst {
                GenericLocation::Memory(x) => {
                    if x.segment_reg.register() == Register::FS {
                        ins_ssa.ss_asgns.iter().for_each(|a| match a.lhs.get_loc() {
                            GenericLocation::Memory(m) => {
                                if m == x {
                                    let rl = match &a.rhs {
                                        GenericExpr::Unary(_, r) => {
                                            Some(r.stringify_expr().unwrap() + ".LABEL")
                                        }
                                        GenericExpr::Imm(_) | GenericExpr::Any(_) => None,
                                        _ => Some(a.rhs.stringify_expr().unwrap() + ".LABEL"),
                                    };

                                    if !rl.is_none() {
                                        let c = Const::new(Sort::Bool, rl.clone().unwrap()).into();
                                        let d = Const::new(Sort::Bool, rl.clone().unwrap()).into();
                                        if !sinks.contains(&rl.clone().unwrap()) {
                                            let fl = expr!(c, boolean!("="), F.clone().into());
                                            sem_rel.push((fl, format!("nonsink {:X}", addr)));
                                        }
                                        let pc = expr!(d, boolean!("="), F.clone().into());
                                        asserts.push((pc, format!("public write 0x{:X}", addr)));
                                    }
                                }
                            }
                            _ => {}
                        });
                    }
                }
                _ => {}
            });

            read_srcs.iter().for_each(|src| match src {
                GenericLocation::Memory(x) => {
                    if x.segment_reg.register() == Register::FS {
                        ins_ssa.ss_asgns.iter().for_each(|a| match a.lhs.get_loc() {
                            GenericLocation::Register(r) => {
                                if r.register() != Register::RIP {
                                    let lhs_label = self.extract_labels(a.lhs.clone());
                                    let lhs_c = Const::new(Sort::Bool, lhs_label).into();
                                    let cons = expr!(lhs_c, boolean!("="), F.clone().into());
                                    sem_rel.push((cons, format!("PR cons 0x{:X}", addr)));
                                }
                            }
                            _ => {}
                        });
                    }
                }
                _ => {}
            });

            let ins_cons = cons.get_mut(addr).unwrap();
            ins_cons.sem_relationships.append(&mut sem_rel);
            ins_cons.assertions.append(&mut asserts);
        }
        Ok(())
    }
}

fn fun_name(
    ssa: &FuncSSA,
    reg: Option<Register>,
    truth_val: Const,
) -> (GenericExpr<Sub<GenericLocation<Sub<Register>>>>, String) {
    let reg_expr = SSExpr::from(ssa.get_initreg(reg.unwrap()).unwrap());
    let reg_label = reg_expr.stringify_expr().unwrap() + ".LABEL";
    let l = Const::new(Sort::Bool, reg_label).into();
    let expr = expr!(l, boolean!("="), truth_val.into());
    (expr, format!("taint  {:?} at function start", reg.unwrap()))
}
