use crate::*;
use anyhow::{anyhow, Result};
use iced_asm::Register;
use log::trace;

// /// The lhs of all the assignments must all be full registers
// pub fn tease_assignments(assignments: &mut Vec<Assignment>) -> Result<()> {
//     let target_sort = Sort::BitVec(64);
//     for a in assignments {
//         if let Location::Register(r) = a.left_hand_side {
//             let sort_lhs = a.left_hand_side.get_sort();
//             if sort_lhs != target_sort {  // not a full register
//                 a.right_hand_side = sort_lhs.cast(target_sort)?(a.right_hand_side.clone());
//                 a.left_hand_side = Location::Register(r.full_register());
//             }
//         }
//     }
//     Ok(())
// }

/// unalias the location
/// currently it only take care of registers
/// GPR -> GPR 64(full register)
/// Vector reg: only allow XMM
pub fn unalias_location(loc: Location) -> Result<Location> {
    match loc {
        Location::Register(r) => Ok(Location::Register(unalias_register(r)?)),
        _ => Ok(loc),
    }
}

pub fn unalias_register(r: Register) -> Result<Register> {
    if r.is_vector_register() {
        if !r.is_xmm() {
            return Err(anyhow!("Only XMM vector registers are supported"));
        }
        Ok(r)
    } else if r.is_gpr() || r.is_ip() || r.is_st() {
        Ok(r.full_register())
    } else {
        Err(anyhow!("Unsupported register type {:?}", r))
    }
}

pub fn tease_assignment(mut a: Assignment) -> Result<Assignment> {
    let target_sort = unalias_location(a.lhs.clone())?.get_sort();
    // trace!("target sort {:?}", target_sort);
    Sort::compatible(a.lhs.get_sort(), a.rhs.infer_sort()?)?;
    if let Location::Register(r) = a.lhs {
        let sort_lhs = a.lhs.get_sort();
        let sort_rhs = a.rhs.infer_sort()?;
        if sort_lhs != target_sort {
            // extend when LHS is not a full register
            a.rhs = sort_rhs.cast(target_sort)?(a.rhs);
            // a.right_hand_side = sort_lhs.cast(target_sort)?(a.right_hand_side);
            a.lhs = unalias_location(Location::Register(r))?;
        }
    }
    let rhs_temp = tease_expr(a.rhs, None)?;
    a.rhs = rhs_temp.infer_sort()?.cast(target_sort)?(rhs_temp);
    Ok(a)
}

/// Remove consecutive duplicated `Extract`s.
/// extract_arg: the argument of the outer `Extract`
/// TODO: deal with extend?
pub fn tease_expr(e: Expr, extract_arg: Option<usize>) -> Result<Expr> {
    trace!(
        "trasing expr {:?}, expr sort: {:?}, extract_arg {:?}",
        e,
        e.infer_sort(),
        extract_arg
    );
    match e {
        Expr::Unary(UnaryOp::BV(BVUnaryOp::Extract(n)), inner_e) => match extract_arg {
            Some(ext) if ext == n => tease_expr(*inner_e, extract_arg),
            _ => Ok(Expr::Unary(
                UnaryOp::BV(BVUnaryOp::Extract(n)),
                Box::new(tease_expr(*inner_e, Some(n))?),
            )),
        },
        Expr::Unary(op, e) => Ok(Expr::Unary(op, Box::new(tease_expr(*e, None)?))),
        Expr::Binary(op, e1, e2) => Ok(Expr::Binary(
            op,
            Box::new(tease_expr(*e1, None)?),
            Box::new(tease_expr(*e2, None)?),
        )),
        Expr::Ite(eif, ethen, eelse) => Ok(Expr::Ite(
            Box::new(tease_expr(*eif, None)?),
            Box::new(tease_expr(*ethen, None)?),
            Box::new(tease_expr(*eelse, None)?),
        )),
        Expr::Var(Location::Register(r)) => {
            if r.is_gpr() || r.is_ip() || r.is_segment_register() {
                Ok(Sort::BitVec(64).cast(e.infer_sort()?)?(Expr::Var(
                    Location::Register(r.full_register()),
                )))
                // TODO: extend to 512-bit registers later
            } else if r.is_vector_register() && r.is_xmm() {
                Ok(Sort::BitVec(128).cast(e.infer_sort()?)?(Expr::Var(
                    Location::Register(r),
                )))
            } else {
                Err(anyhow!(
                    "Cannot find a valid case to deal with the register: {:?}",
                    r
                ))
            }
        }
        e => Ok(e),
    }
}
