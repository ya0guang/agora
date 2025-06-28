use crate::dis::Disassembled;
use crate::ssa::*;
use anyhow::{anyhow, Result};
use ir::*;
use log::warn;
use std::collections::HashMap;
use std::collections::{BTreeMap, HashSet};

pub type AssertWithInfo = (SSExpr, String);

#[derive(Debug)]
pub struct TotalProof {
    pub hints: Vec<(String, Option<SSRel>)>,
    // the assertion need to be checked for true before any other constraints, derived from hints
    pub prf_precondition: Vec<AssertWithInfo>,
    pub sem_assignments: Vec<SSAsgn>,
    // relationships from the proof, which are checked
    pub prf_relationships: Vec<SSRel>,
    // relationships from the semantics
    pub sem_relationships: Vec<SSRel>,
    // // SMT constraints & debug info
    // pub assertions: Vec<AssertWithInfo>,
}

impl TotalProof {
    fn new() -> TotalProof {
        TotalProof {
            hints: vec![],
            prf_precondition: vec![],
            sem_assignments: vec![],
            prf_relationships: vec![],
            sem_relationships: vec![],
            // assertions: vec![],
        }
    }
}

pub fn process_proof(
    // How to use IntoIterator trait bound on disassembled?
    disassembled: &Disassembled,
    semantics: &FuncSSA,
    proof: &HashMap<u64, Vec<Proof>>,
) -> Result<BTreeMap<u64, TotalProof>> {
    let mut result = BTreeMap::new();

    // TODO: Handle the magic sequence from CONFLLVM.
    // There should be a better place to do this.
    // let magic = proof.get_key_value(proof.keys().sorted().into_iter().nth(0).unwrap());
    // if !magic.is_none() {
    //     magic.unwrap().1.iter().for_each(|p| match p {
    //         Proof::Hint(policy, _) => {
    //             if policy.starts_with("MAGIC 0x") {
    //                 let mut cons = TotalProof::new();
    //                 cons.hints.push((policy.clone(), None));
    //                 result.insert(0, cons);
    //             }
    //         }
    //         _ => {}
    //     });
    // }
    for (addr, proofs) in proof {
        for p in proofs {
            match p {
                Proof::Hint(policy, _) => {
                    if policy.starts_with("MAGIC 0x") {
                        let mut cons = TotalProof::new();
                        cons.hints.push((policy.clone(), None));
                        result.insert(*addr, cons);
                    }
                }
                _ => {}
            }
        }
    }

    for (addr, _ins) in disassembled {
        // Convert Proof to Constraints
        let mut cons = TotalProof::new();
        if let None = proof.get(addr) {
            result.insert(*addr, cons);
            continue;
        };
        warn!("Processing addr 0x{:x?}", addr);
        warn!("Processing addr 0x{:x?}", _ins);
        // warn!("Processing addr 0x{:x?}", semantics.ssa_map.get(addr));
        let (mut proof_iter, mut sem_asgn_iter, mut sem_rel_iter) = (
            proof.get(addr).unwrap().iter(),
            semantics.ssa_map.get(addr).unwrap().ss_asgns.iter(),
            semantics.ssa_map.get(addr).unwrap().ss_rels.iter(),
        );
        let (mut proof_iter_pointer, mut sem_asgn_iter_pointer, mut sem_rel_iter_pointer) =
            (proof_iter.next(), sem_asgn_iter.next(), sem_rel_iter.next());
        let ssa = &semantics.ssa_map.get(addr).unwrap().ssa;
        // trace!(
        //     "Assignments: {:X?}",
        //     semantics.ssa_map.get(addr).unwrap().ss_asgns
        // );
        // trace!("Proof: {:X?}", proof.get(addr).unwrap());
        let mut temp_assignments_set = HashSet::new();

        let mut temp_relationships_set = HashSet::new();
        while let Some(a) = sem_asgn_iter_pointer {
            if proof_iter_pointer.is_none() {
                break;
            }
            match proof_iter_pointer.unwrap() {
                Proof::Asgn(pa) => match validate_convert_assignment(pa, a) {
                    Ok(va) => {
                        temp_assignments_set.insert(va);
                        proof_iter_pointer = proof_iter.next();
                        sem_asgn_iter_pointer = sem_asgn_iter.next();
                    }
                    Err(e) => {
                        warn!("Mismatched proof, trying to match next one: {}", e);
                        sem_asgn_iter_pointer = sem_asgn_iter.next();
                    }
                },
                // Currently the relationships are check to be sat in the solver
                Proof::Rel(pr) => {
                    let vr = convert_rel(pr, ssa)?;
                    match sem_rel_iter_pointer {
                        Some(sr) if vr == *sr => {
                            cons.sem_relationships.push(vr.clone());
                            sem_rel_iter_pointer = sem_rel_iter.next();
                        }
                        _ => {
                            cons.prf_relationships.push(vr);
                            // The relationship should be derived from the complete assignment semantics
                            // So we also add all semantics to cons
                            for a in semantics.ssa_map.get(addr).unwrap().ss_asgns.iter() {
                                temp_assignments_set.insert(a.clone());
                            }
                            for a in semantics.ssa_map.get(addr).unwrap().ss_rels.iter() {
                                temp_relationships_set.insert(a.clone());
                            }
                        }
                    }
                    proof_iter_pointer = proof_iter.next();
                }
                Proof::Hint(policy, ph) => {
                    cons.hints.push((
                        policy.clone(),
                        match ph {
                            Some(rel) => Some(convert_rel(rel, ssa)?),
                            None => None,
                        },
                    ));
                    proof_iter_pointer = proof_iter.next();
                }
                Proof::Anno(_) => {
                    unimplemented!()
                }
            }
        }
        if !proof_iter_pointer.is_none() {
            // return Err(anyhow!("Not every line of proof is validated"));
            warn!("Quick check fails on addr 0x{:x?}", addr);
            for a in semantics.ssa_map.get(addr).unwrap().ss_asgns.iter() {
                temp_assignments_set.insert(a.clone());
            }
            for a in semantics.ssa_map.get(addr).unwrap().ss_rels.iter() {
                temp_relationships_set.insert(a.clone());
            }
        }
        for a in temp_assignments_set {
            cons.sem_assignments.push(a);
        }
        for r in temp_relationships_set {
            cons.sem_relationships.push(r.clone());
        }
        result.insert(*addr, cons);
    }
    Ok(result)
}

fn validate_convert_assignment(proof_asgn: &Assignment, ssa_asgn: &SSAsgn) -> Result<SSAsgn> {
    let ssa_lhs = ssa_asgn.lhs.clone();
    if <LocationSub as std::convert::Into<Location>>::into(ssa_lhs.clone()) != proof_asgn.lhs {
        return Err(anyhow!("LHS mismatch"));
    }

    // Substitute these lines to filter out non-stack memory modeling
    // #[cfg(feature = "naive_memory")]
    // let ssa_rhs = if let GenericLocation::Memory(m) = ssa_lhs.location && !m.rsp_ralted() {
    //     Expr::Any(ssa_asgn.right_hand_side.infer_sort()?.into())
    // } else {
    //     // We may only model the stack memory
    //     ssaexpr_to_expr(&ssa_asgn.right_hand_side.clone())
    // };

    let ssa_rhs = ssaexpr_to_expr(&ssa_asgn.rhs.clone());
    // #[cfg(not(feature = "naive_memory"))]
    // let ssa_rhs = if let GenericLocation::Memory(_) = ssa_lhs.location {
    //     Expr::Any(ssa_lhs.get_sort().into())
    // } else {
    //     havoc_memory_read(ssaexpr_to_expr(&ssa_asgn.right_hand_side.clone()))
    // };

    // if let GenericExpr::Ite(_, _, _) = ssa_rhs {
    // } else
    if ssa_rhs != proof_asgn.rhs {
        return Err(anyhow!("RHS mismatch"));
    }
    Ok(SSAsgn {
        lhs: ssa_lhs,
        rhs: if let Expr::Any(s) = ssa_rhs {
            SSExpr::Any(s)
        } else {
            ssa_asgn.rhs.clone()

            // #[cfg(not(feature = "naive_memory"))]
            // {
            //     havoc_memory_read(ssa_asgn.right_hand_side.clone())
            // }
        },
    })
}

pub fn convert_rel(proof_rel: &Relationship, ssa: &SSAState) -> Result<SSRel> {
    Ok(SSRel {
        relationship: proof_rel.relationship.clone(),
        lhs: expr_to_ssexpr(&proof_rel.lhs, ssa)?,
        rhs: expr_to_ssexpr(&proof_rel.rhs, ssa)?,
    })
}

pub fn expr_to_ssexpr(expr: &Expr, ssa: &SSAState) -> Result<SSExpr> {
    match expr {
        Expr::Any(s) => Ok(SSExpr::Any(s.clone())),
        Expr::Alias(a) => Ok(SSExpr::Alias(a.clone())),
        Expr::Const(c) => Ok(SSExpr::Const(c.clone())),
        Expr::Var(v) => Ok(SSExpr::Var(
            ssa.get_loc_ssa(&ssa.convert_to_ss(v))
                .ok_or(anyhow!("Cannot find {:?} in SSA", v))?,
        )),
        Expr::Imm(i) => Ok(SSExpr::Imm(i.clone())),
        Expr::Unary(uop, e) => Ok(SSExpr::Unary(
            uop.clone(),
            Box::new(expr_to_ssexpr(e, ssa)?),
        )),
        Expr::Binary(bop, e1, e2) => Ok(SSExpr::Binary(
            bop.clone(),
            Box::new(expr_to_ssexpr(e1, ssa)?),
            Box::new(expr_to_ssexpr(e2, ssa)?),
        )),
        Expr::Ite(cond, ethen, eelse) => Ok(SSExpr::Ite(
            Box::new(expr_to_ssexpr(cond, ssa)?),
            Box::new(expr_to_ssexpr(ethen, ssa)?),
            Box::new(expr_to_ssexpr(eelse, ssa)?),
        )),
    }
}

fn ssaexpr_to_expr(proof_expr: &SSExpr) -> Expr {
    match proof_expr {
        SSExpr::Any(s) => Expr::Any(s.clone()),
        SSExpr::Alias(a) => Expr::Alias(a.clone()),
        SSExpr::Const(c) => Expr::Const(c.clone()),
        SSExpr::Var(v) => Expr::Var(<LocationSub as std::convert::Into<Location>>::into(
            v.clone(),
        )),
        SSExpr::Imm(i) => Expr::Imm(i.clone()),
        SSExpr::Unary(uop, e) => Expr::Unary(uop.clone(), Box::new(ssaexpr_to_expr(e))),
        SSExpr::Binary(bop, e1, e2) => Expr::Binary(
            bop.clone(),
            Box::new(ssaexpr_to_expr(e1)),
            Box::new(ssaexpr_to_expr(e2)),
        ),
        SSExpr::Ite(cond, ethen, eelse) => Expr::Ite(
            Box::new(ssaexpr_to_expr(cond)),
            Box::new(ssaexpr_to_expr(ethen)),
            Box::new(ssaexpr_to_expr(eelse)),
        ),
    }
}

// #[cfg(not(feature = "naive_memory"))]
// fn havoc_memory_read<T>(expr: GenericExpr<T>) -> GenericExpr<T>
// where
//     T: Clone + LocationType + Sorted,
// {
//     match expr {
//         GenericExpr::Any(_) | GenericExpr::Imm(_) | GenericExpr::Const(_, _) => expr,
//         GenericExpr::Var(ref v) => {
//             if v.is_memory() {
//                 GenericExpr::Any(v.get_sort().into())
//             } else {
//                 expr
//             }
//         }
//         GenericExpr::Unary(uop, e) => {
//             GenericExpr::Unary(uop, Box::new(havoc_memory_read(*e.clone())))
//         }
//         GenericExpr::Binary(bop, e1, e2) => GenericExpr::Binary(
//             bop,
//             Box::new(havoc_memory_read(*e1.clone())),
//             Box::new(havoc_memory_read(*e2.clone())),
//         ),
//         GenericExpr::Ite(cond, ethen, eelse) => GenericExpr::Ite(
//             Box::new(havoc_memory_read(*cond.clone())),
//             Box::new(havoc_memory_read(*ethen.clone())),
//             Box::new(havoc_memory_read(*eelse.clone())),
//         ),
//     }
// }
