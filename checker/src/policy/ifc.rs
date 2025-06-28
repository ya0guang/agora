use super::Matcher;
use crate::dis::{ControlFlowInfo, Disassembled};
use crate::policy::Constraints;
use crate::ssa::*;
use crate::validate::*;
use anyhow::Result;
use iced_asm::{Mnemonic, Register};
use ir::smt::StringifySym;
use ir::*;
use lazy_static::lazy_static;
use log::debug;
use smt::StringifyExpr;
use std::collections::BTreeMap;
use std::vec;

lazy_static! {
    static ref FALSE_STRING: Const = Const::new(Sort::Bool, "false".to_string());
    static ref TRUE_STRING: Const = Const::new(Sort::Bool, "true".to_string());
}

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
                            debug!("\x1b[92mSECRET\x1b[0m: {:?}", x);
                            secmem.push(self.extract_labels(v));
                        }
                    }
                    _ => {}
                }
            }
            GenericExpr::Imm(_) => labels.push("false".to_string()),
            _ => {
                unimplemented!("EXPR: {:?}", expr.stringify_expr().unwrap());
            }
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
        constraints: &mut BTreeMap<u64, Constraints>,
        start_addr: &u64,
    ) {
        let taint_regs = vec![
            None,
            Some(Register::RAX),
            Some(Register::RDI),
            Some(Register::RSI),
            Some(Register::RDX),
            Some(Register::RCX),
            Some(Register::R8),
            Some(Register::R9),
        ];
        // for 1 to 8
        for i in (0..taint_regs.len()).rev() {
            let var_name = bits.clone() & 1;
            let taint = var_name;
            bits = bits >> 1;
            let reg = taint_regs[i];
            if reg.is_none() {
                continue;
            }
            let truth_val = match taint {
                0 => FALSE_STRING.clone(),
                1 => TRUE_STRING.clone(),
                _ => unreachable!(),
            };
            if i == 1 && taint == 0 {
                debug!(
                    "FIND_DEF_REACHING_RET: {:?}",
                    self.find_def_reaching_ret(&Register::RAX, ssa, dis, cfi)
                );
                for def in self.find_def_reaching_ret(&Register::RAX, ssa, dis, cfi) {
                    if def.is_none() {
                        continue;
                    }
                    let ssdef = SSExpr::from(def.unwrap());
                    let reg_label = ssdef.stringify_expr().unwrap() + ".LABEL";
                    let reg_label_expr = expr!(
                        Const::new(Sort::Bool, reg_label).into(),
                        boolean!("="),
                        FALSE_STRING.clone().into()
                    );
                    let reg_label_check = (
                        reg_label_expr,
                        format!("taint check for register {:?} at function return", reg),
                    );
                    constraints
                        .get_mut(&start_addr)
                        .unwrap()
                        .sem_relationships
                        .push(reg_label_check);
                }
                continue;
            }
            let reg_label_check = fun_name(ssa, reg, truth_val);
            constraints
                .get_mut(&start_addr)
                .unwrap()
                .sem_relationships
                .push(reg_label_check);
        }
    }
}

impl Matcher for IFCSafe {
    fn match_function(
        &self,
        ssa: &FuncSSA,
        dis: &Disassembled,
        proofs: &BTreeMap<u64, TotalProof>,
        constraints: &mut BTreeMap<u64, Constraints>,
        cfi: &ControlFlowInfo,
    ) -> Result<()> {
        // handling magic sequence
        let start_addr = dis.first_key_value().unwrap().0;
        let hints = proofs.get(&(start_addr - 0x10)).unwrap().hints.clone();
        let magic = hints.into_iter().next().unwrap().0;
        let bits = i64::from_str_radix(&magic[8..10], 16).unwrap();
        self.magic_sequence_handling(bits, ssa, dis, cfi, constraints, start_addr);

        let mut sinks = vec![];

        for (addr, ins_ssa) in &ssa.ssa_map {
            let ins = dis.get(addr).unwrap();
            let mut sem_rel = vec![];
            let mut asserts = vec![];

            if ins.mnemonic() == Mnemonic::Call {
                assert_ne!(cfi.bb_of_ins(*addr).unwrap().0, *addr);
                let prev_ins_addr = dis.keys().rev().skip_while(|&x| x >= addr).next().unwrap();
                let f_addr = ins.memory_displacement64();
                debug!("0x{:x}\x1b[93m CALL\x1b[0m:  {:x?}", addr, f_addr);
                let tmp = proofs.get(&(f_addr - 0x10));
                debug!("0x{:x} tmp: {:?}", addr, tmp);
                if tmp.is_none() || tmp.unwrap().hints.len() == 0 {
                    continue;
                }
                let call_magic = proofs.get(&(f_addr - 0x10)).unwrap().hints.clone();
                let mut bits =
                    i64::from_str_radix(&call_magic.into_iter().next().unwrap().0[8..10], 16)
                        .unwrap();
                debug!("0x{:x}\x1b[93m MAGIC\x1b[0m: {:08b}", addr, bits);

                let taint_regs = vec![
                    None,
                    Some(Register::RAX),
                    Some(Register::RDI),
                    Some(Register::RSI),
                    Some(Register::RDX),
                    Some(Register::RCX),
                    Some(Register::R8),
                    Some(Register::R9),
                ];

                for i in (0..taint_regs.len()).rev() {
                    let var_name = bits.clone() & 1;
                    let taint = var_name;
                    bits = bits >> 1;
                    let reg = taint_regs[i];
                    if reg.is_none() {
                        continue;
                    }
                    let truth_val = match taint {
                        0 => FALSE_STRING.clone(),
                        1 => TRUE_STRING.clone(),
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
                    let reg_label_expr = expr!(
                        Const::new(Sort::Bool, reg_label).into(),
                        boolean!("="),
                        truth_val.into()
                    );
                    debug!("0x{:x} {:?}", addr, reg_label_expr);
                    let reg_label_check = (
                        reg_label_expr,
                        format!("taint check for register {:?} at function return", reg),
                    );
                    constraints
                        .get_mut(&start_addr)
                        .unwrap()
                        .sem_relationships
                        .push(reg_label_check);
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
                        _ => {
                            sinks.push(lhs.stringify_sym().unwrap() + ".LABEL");
                            // log saying added a sink label
                            debug!(
                                "0x{:x} \x1b[95mADDED SINK LABEL\x1b[0m: {:?}",
                                addr,
                                lhs.stringify_sym().unwrap() + ".LABEL"
                            );
                        }
                    },
                    GenericLocation::Flag(_) | GenericLocation::MAS(_) => continue,
                    _ => {}
                }
                match rhs {
                    GenericExpr::Any(_) => continue,
                    _ => {}
                }
                debug!(
                    "0x{:x}\x1b[96m ASSIGNMENT\x1b[0m {:?} = {:?}",
                    addr, lhs, rhs
                );

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
                        let pub_cons = expr!(
                            FALSE_STRING.clone().into(),
                            boolean!("="),
                            Const::new(Sort::Bool, label.to_string()).into()
                        );
                        sem_rel.push((pub_cons, format!("nonsink {:X}", addr)));
                    }

                    let d = if Const::new(Sort::Bool, label.to_string()) == FALSE_STRING.clone() {
                        boolean!("=>")
                    } else {
                        boolean!("=")
                    };
                    let assign_cons = expr!(
                        Const::new(Sort::Bool, label.to_string()).into(),
                        d,
                        Const::new(Sort::Bool, lhs_label.clone()).into()
                    );
                    debug!(
                        "0x{:x} \x1b[96mASSIGNMENT RELATION\x1b[0m: {:?}",
                        addr, assign_cons
                    );
                    sem_rel.push((
                        assign_cons,
                        format!("assignment relation constraint at 0x{:X}", addr),
                    ));
                }

                for label in rhs_label.1.iter() {
                    let sec_cons = expr!(
                        Const::new(Sort::Bool, label.to_string()).into(),
                        boolean!("="),
                        TRUE_STRING.clone().into()
                    );
                    sem_rel.push((sec_cons, format!("secret read check at 0x{:X}", addr)));
                }
            }

            let write_dsts: Vec<_> = ins_ssa
                .written_locations
                .clone()
                .into_iter()
                .filter(|x| x.is_memory())
                .collect();
            assert!(write_dsts.len() <= 1);
            let read_srcs: Vec<_> = ins_ssa
                .read_locations
                .clone()
                .into_iter()
                .filter(|x| x.is_memory())
                .collect();
            assert!(read_srcs.len() <= 1);

            write_dsts.iter().for_each(|dst| match dst {
                GenericLocation::Memory(x) => {
                    if x.segment_reg.register() == Register::FS {
                        debug!("0x{:x}\x1b[91m WRITE INTO PUBLIC\x1b[0m: {:x?}", addr, x);
                        ins_ssa.ss_asgns.iter().for_each(|a| match a.lhs.get_loc() {
                            GenericLocation::Memory(m) => {
                                debug!("0x{:x}: {:x?}", addr, a);
                                if m == x {
                                    debug!("0x{:x} \x1b[94msource\x1b[0m: {:x?}", addr, a.rhs);
                                    debug!("0x{:x} \x1b[94msink  \x1b[0m: {:x?}", addr, a.lhs);
                                    debug!("0x{:x}: {:x?}", addr, ins_ssa.ss_asgns);
                                    let rhs_label = match &a.rhs {
                                        GenericExpr::Unary(_, r) => {
                                            Some(r.stringify_expr().unwrap() + ".LABEL")
                                        }
                                        GenericExpr::Imm(_) | GenericExpr::Any(_) => None,
                                        _ => {
                                            debug!(
                                                "0x{:x} \x1b[94mlabel\x1b[0m: {:x?}",
                                                addr, a.rhs
                                            );
                                            Some(a.rhs.stringify_expr().unwrap() + ".LABEL")
                                        }
                                    };

                                    debug!("0x{:x} \x1b[94mlabel\x1b[0m: {:x?}", addr, rhs_label);

                                    if !rhs_label.is_none() {
                                        if !sinks.contains(&rhs_label.clone().unwrap()) {
                                            debug!(
                                                "0x{:x} \x1b[94mnonsink!!!\x1b[0m: {:?}",
                                                addr, a.rhs
                                            );
                                            let pub_cons = expr!(
                                                Const::new(Sort::Bool, rhs_label.clone().unwrap())
                                                    .into(),
                                                boolean!("="),
                                                FALSE_STRING.clone().into()
                                            );
                                            sem_rel.push((pub_cons, format!("nonsink {:X}", addr)));
                                        }
                                        let pub_cons = expr!(
                                            Const::new(Sort::Bool, rhs_label.clone().unwrap())
                                                .into(),
                                            boolean!("="),
                                            FALSE_STRING.clone().into()
                                        );
                                        debug!(
                                            "0x{:x} \x1b[94mPW chk\x1b[0m: {:x?}",
                                            addr, pub_cons
                                        );
                                        asserts.push((
                                            pub_cons,
                                            format!("public write check at 0x{:X}", addr),
                                        ));
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
                    if x.segment_reg.register() == Register::GS {
                        debug!("0x{:x}\x1b[92m READ FROM SECRET\x1b[0m: {:x?}", addr, src);
                    } else if x.segment_reg.register() == Register::FS {
                        debug!("0x{:x}\x1b[95m READ FROM PUBLIC\x1b[0m: {:x?}", addr, src);
                        ins_ssa.ss_asgns.iter().for_each(|a| match a.lhs.get_loc() {
                            GenericLocation::Register(r) => {
                                if r.register() != Register::RIP {
                                    debug!("0x{:x}: {:x?}", addr, a);
                                    debug!("0x{:x} \x1b[94msource\x1b[0m: {:?}", addr, a.rhs);
                                    debug!("0x{:x} \x1b[94mdestination\x1b[0m: {:?}", addr, a.lhs);
                                    let lhs_label = self.extract_labels(a.lhs.clone());
                                    let cons = expr!(
                                        Const::new(Sort::Bool, lhs_label).into(),
                                        boolean!("="),
                                        FALSE_STRING.clone().into()
                                    );
                                    debug!("0x{:x} \x1b[94mPW chk\x1b[0m: {:?}", addr, cons);
                                    sem_rel
                                        .push((cons, format!("public read check at 0x{:X}", addr)));
                                }
                            }
                            _ => {}
                        });
                    }
                }
                _ => {}
            });

            if ins.mnemonic() == Mnemonic::Pop && ins.op0_register() == Register::RBP {
                // check the next instruction is : mov    (%rsp),%r10
                let next_addr = ins.next_ip();
                let next_ins = dis.get(&next_addr).unwrap();
                debug!("POP: 0x{:x}: {:?}", ins.next_ip(), next_ins);
            }

            let ins_cons = constraints.get_mut(addr).unwrap();
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
    let reg_label_expr = expr!(
        Const::new(Sort::Bool, reg_label).into(),
        boolean!("="),
        truth_val.into()
    );
    let reg_label_check = (
        reg_label_expr,
        format!("taint of register {:?} at function start", reg.unwrap()),
    );
    reg_label_check
}
