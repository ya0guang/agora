use crate::{ast::*, traits::*, LocationSub};
use anyhow::{anyhow, Result};
use std::{cmp::max, fmt::Debug};

// Sort

// LHS (location) => sort trait

/// Sort is the type in SMT solver
/// data/sort => declare data type of sort
#[derive(Debug, PartialEq, Clone, Copy, PartialOrd, Eq, Ord, Hash)]
pub enum Sort {
    Bool,
    BitVec(usize),
}

impl From<ValSize> for Sort {
    fn from(size: ValSize) -> Self {
        if size.size_bits() == 1 {
            Sort::Bool
        } else {
            Sort::BitVec(size.size_bits())
        }
    }
}

impl TryFrom<usize> for Sort {
    type Error = anyhow::Error;

    fn try_from(value: usize) -> Result<Sort> {
        let r = if value == 1 {
            Sort::Bool
        } else {
            Sort::BitVec(value)
        };
        r.validate()?;
        Ok(r)
    }
}

type Continuation<T> = Box<dyn Fn(GenericExpr<T>) -> GenericExpr<T>>;

impl Sort {
    pub fn validate(&self) -> Result<()> {
        match self {
            Sort::Bool => Ok(()),
            Sort::BitVec(n)
                if *n == 8 || *n == 16 || *n == 32 || *n == 64 || *n == 80 || *n == 128 =>
            {
                Ok(())
            }
            _ => Err(anyhow!("Invalid sort!")),
        }
    }

    /// Get the maximum sort of two sorts
    pub fn compatible(s1: Sort, s2: Sort) -> Result<Sort> {
        match (s1, s2) {
            (Sort::Bool, Sort::Bool) => Ok(Sort::Bool),
            (Sort::BitVec(_), Sort::BitVec(_)) => Ok(max(s1, s2)),
            _ => Err(anyhow!("Bool and BitVec are not compatible!")),
        }
    }

    // TODO deal with signed/unsigned
    pub fn cast<T>(self, target: Sort) -> Result<Continuation<T>> {
        self.validate()?;
        target.validate()?;
        match (self, target) {
            (Sort::Bool, Sort::Bool) => Ok(Box::new(|e| e)),
            (Sort::BitVec(ns), Sort::BitVec(nt)) if ns == nt => Ok(Box::new(|e| e)),
            (Sort::BitVec(ns), Sort::BitVec(nt)) if ns < nt => Ok(Box::new(move |e| {
                GenericExpr::Unary(UnaryOp::BV(BVUnaryOp::ZExtend(nt - ns)), Box::new(e))
            })),
            (Sort::BitVec(ns), Sort::BitVec(nt)) if ns > nt =>
            // TODO: take care of this case!!!
            {
                Ok(Box::new(move |e| {
                    GenericExpr::Unary(UnaryOp::BV(BVUnaryOp::Extract(nt - 1)), Box::new(e))
                }))
            }
            _ => Err(anyhow!("Cannot cast sort!")),
        }
    }
}

pub trait Sorted {
    fn get_sort(&self) -> Sort;
}

impl Sorted for Alias {
    fn get_sort(&self) -> Sort {
        self.size.get_sort()
    }
}

impl Sorted for ValSize {
    fn get_sort(&self) -> Sort {
        self.clone().into()
    }
}

impl<T: RegisterTrait + Copy> Sorted for GenericLocation<T> {
    fn get_sort(&self) -> Sort {
        match self {
            GenericLocation::Flag(_) | GenericLocation::MAS(_) => Sort::Bool,
            GenericLocation::Register(r) => (r.size() * 8).try_into().unwrap(),
            GenericLocation::Memory(m) => m.size.into(),
            GenericLocation::Stack(s) => s.size.into(),
        }
    }
}

impl Sorted for LocationSub {
    fn get_sort(&self) -> Sort {
        self.loc.get_sort()
    }
}

/// Infer the sort of an AST node
pub trait SortInfer {
    // maybe we need a environment?
    fn infer_sort(&self) -> Result<Sort>;
}

pub trait SortChecker {
    fn check_sort(&self) -> Result<()>;
}

impl<L: LHSValue + Sorted + Debug, T> SortChecker for GenericAssignment<L, T>
where
    GenericExpr<T>: RHSValue + SortInfer,
{
    fn check_sort(&self) -> Result<()> {
        if self.lhs.get_sort() == self.rhs.infer_sort()? {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Sort checking fail for assignment"))
        }
    }
}

impl<T> SortChecker for GenericRelationship<T>
where
    GenericExpr<T>: SortInfer,
{
    fn check_sort(&self) -> Result<()> {
        if self.lhs.infer_sort()? == self.rhs.infer_sort()? {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Sort checking fail for relationship"))
        }
    }
}

impl<T: RegisterTrait + Copy> SortInfer for GenericLocation<T> {
    // maybe we need a environment?
    fn infer_sort(&self) -> Result<Sort> {
        Ok(self.get_sort())
    }
}

impl<T> SortInfer for GenericExpr<T>
where
    T: Sorted + Debug,
{
    // maybe we need a environment?
    fn infer_sort(&self) -> Result<Sort> {
        // trace!("infer sort for {:?}", &self);
        match self {
            GenericExpr::Any(s) => Ok(s.get_sort()),
            GenericExpr::Const(c) => Ok(c.sort),
            GenericExpr::Alias(a) => Ok(a.get_sort()),
            GenericExpr::Imm(i) => Ok(i.size.get_sort()),
            GenericExpr::Var(v) => Ok(v.get_sort()),
            // TODO: need to pay more attention on this!!!!
            GenericExpr::Unary(UnaryOp::Boolean(_), exp) => {
                assert_eq!(exp.infer_sort()?, Sort::Bool);
                Ok(Sort::Bool)
            }
            GenericExpr::Unary(UnaryOp::BV(uop), exp) => match uop {
                BVUnaryOp::Neg | BVUnaryOp::Not => exp.infer_sort(),
                BVUnaryOp::ZExtend(i) => match exp.infer_sort()? {
                    Sort::BitVec(n) => Ok(Sort::BitVec(n + (*i as usize))),
                    _ => Err(anyhow::anyhow!("ZExtend must be applied to bitvectors")),
                },
                BVUnaryOp::Extract(i) => {
                    match exp.infer_sort()? {
                        // ((_ extract i j) (_ BitVec m) (_ BitVec n))
                        // - extraction of bits i down to j from a bitvector of size m to yield a
                        Sort::BitVec(n) if n > *i => Ok(Sort::BitVec(i + 1)),
                        _ => Err(anyhow::anyhow!(
                            "Extract must be applied to bitvectors of sufficient size"
                        )),
                    }
                }
                BVUnaryOp::Memory(_) => {
                    assert_eq!(
                        exp.infer_sort()?,
                        Sort::BitVec(64),
                        "Memory address must be 64 bits"
                    );
                    // Currently we only support 64-bit memory read
                    Ok(Sort::BitVec(64))
                }
            },
            GenericExpr::Binary(BinaryOp::Boolean(_), e1, e2) => {
                assert_eq!(e1.infer_sort()?, Sort::Bool);
                assert_eq!(e2.infer_sort()?, Sort::Bool);
                Ok(Sort::Bool)
            }
            // TODO: need to pay more attention on this!!!!
            // Handled SHL but there may exist more cases of sort mismatch.
            GenericExpr::Binary(BinaryOp::BV(bop), e1, e2) => match bop {
                BVBinaryOp::Arith(op) => {
                    if *op == BVBinaryArith::Shl {
                        return Ok(e1.infer_sort()?);
                    }
                    check_sort_eq(e1.as_ref(), e2.as_ref())
                }
                BVBinaryOp::Relation(_) => match check_sort_eq(e1.as_ref(), e2.as_ref())? {
                    Sort::Bool => Err(anyhow::anyhow!("Sort mismatch")),
                    Sort::BitVec(_) => Ok(Sort::Bool),
                },
            },
            GenericExpr::Ite(cond, ethen, eelse) => {
                if cond.infer_sort()? != Sort::Bool {
                    return Err(anyhow::anyhow!("Condition of ITE must be boolean"));
                } else {
                    return check_sort_eq(ethen.as_ref(), eelse.as_ref());
                }
            }
        }
    }
}

fn check_sort_eq<T: SortInfer>(s1: &T, s2: &T) -> Result<Sort> {
    if s1.infer_sort()? == s2.infer_sort()? {
        Ok(s1.infer_sort()?)
    } else {
        Err(anyhow::anyhow!("Sort mismatch"))
    }
}
