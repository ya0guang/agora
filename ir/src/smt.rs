use crate::traits::*;
use crate::typer::*;
use crate::*;
use anyhow::{anyhow, Result};
use rsmt2::print::{Expr2Smt, Sort2Smt, Sym2Smt};

// Sorts

/// This invoked by XXX2smt for interfacing smt solver while at the same time provide an interface for debugging purpose
pub trait StringifySort {
    fn stringify_sort(&self) -> Result<String>;
}

impl StringifySort for dyn Sorted {
    fn stringify_sort(&self) -> Result<String> {
        self.get_sort().stringify_sort()
    }
}

pub trait StringifySym {
    fn stringify_sym(&self) -> Result<String>;
}

pub trait StringifyExpr {
    fn stringify_expr(&self) -> Result<String>;
}

macro_rules! impl_Sort2Smt {
    ($target_struct:ident <$($generic_param:ident)?>) => {
        impl<$($generic_param)?> Sort2Smt for $target_struct<$($generic_param)?> {
            fn sort_to_smt2<Writer: std::io::Write>(&self, w: &mut Writer) -> rsmt2::SmtRes<()> {
                w.write(self.stringify_sort().unwrap().as_bytes())?;
                Ok(())
            }
        }
    };

    ($target_struct:ident) => {
        impl_Sort2Smt!($target_struct<>);
    }
}

macro_rules! impl_Sym2Smt {
    ($target_struct:ident <$($generic_param:ident)?>) => {
        impl<$($generic_param)?> Sym2Smt for $target_struct<$($generic_param)?> {
            fn sym_to_smt2<Writer: std::io::Write>(&self, w: &mut Writer, _: ()) -> rsmt2::SmtRes<()> {
                w.write(self.stringify_sym().unwrap().as_bytes())?;
                Ok(())
            }
        }
    };

    ($target_struct:ident) => {
        impl_Sym2Smt!($target_struct<>);
    }
}

macro_rules! impl_Expr2Smt {
    ($target_struct:ident <$($generic_param:ident $(: $constraint: ident)?)?>) => {
        impl<$($generic_param $(:$constraint)?)?> Expr2Smt for $target_struct<$($generic_param)?> {
            fn expr_to_smt2<Writer: std::io::Write>(&self, w: &mut Writer, _: ()) -> rsmt2::SmtRes<()> {
                w.write(self.stringify_expr().unwrap().as_bytes())?;
                Ok(())
            }
        }
    };
}

impl StringifySort for Sort {
    fn stringify_sort(&self) -> Result<String> {
        match self {
            Sort::Bool => Ok("Bool".to_string()),
            Sort::BitVec(size) => Ok(format!("(_ BitVec {})", size)),
        }
    }
}

impl_Sort2Smt!(Sort);

impl_Sort2Smt!(Const);

impl_Sort2Smt!(Alias);

impl StringifySort for Alias {
    fn stringify_sort(&self) -> Result<String> {
        self.get_sort().stringify_sort()
    }
}

/// AST nodes

impl<T: RegisterTrait + Copy> StringifySort for GenericLocation<T> {
    fn stringify_sort(&self) -> Result<String> {
        self.infer_sort()?.stringify_sort()
    }
}

// impl_Sort2Smt!(GenericLocation<T: AsRegister>);

impl<T: RegisterTrait + Copy> Sort2Smt for GenericLocation<T> {
    fn sort_to_smt2<Writer: std::io::Write>(&self, w: &mut Writer) -> rsmt2::SmtRes<()> {
        w.write(self.stringify_sort().unwrap().as_bytes())?;
        Ok(())
    }
}

impl StringifySort for LocationSub {
    fn stringify_sort(&self) -> Result<String> {
        self.loc.stringify_sort()
    }
}

impl StringifySort for Const {
    fn stringify_sort(&self) -> Result<String> {
        self.sort.stringify_sort()
    }
}

impl_Sort2Smt!(LocationSub);

// Semantics/Proof AST nodes

impl StringifySym for UnaryOp {
    // TODO: taking care of bool values (maybe)
    fn stringify_sym(&self) -> Result<String> {
        Ok(self.output_prf())
    }
}

impl_Sym2Smt!(UnaryOp);

impl StringifySym for BinaryOp {
    // TODO: taking care of bool values (maybe)
    fn stringify_sym(&self) -> Result<String> {
        Ok(self.output_prf())
    }
}

impl StringifySym for BVBinaryArith {
    fn stringify_sym(&self) -> Result<String> {
        Ok(self.output_prf())
    }
}

impl_Sym2Smt!(BVBinaryArith);

impl_Sym2Smt!(Alias);

impl StringifySym for BVBinaryRelation {
    fn stringify_sym(&self) -> Result<String> {
        Ok(self.output_prf())
    }
}

impl_Sym2Smt!(BVBinaryRelation);

impl StringifySym for BVBinaryOp {
    fn stringify_sym(&self) -> Result<String> {
        match self {
            BVBinaryOp::Arith(ba) => ba.stringify_sym(),
            BVBinaryOp::Relation(br) => br.stringify_sym(),
        }
    }
}

impl_Sym2Smt!(BVBinaryOp);

impl StringifySym for LocationSub {
    fn stringify_sym(&self) -> Result<String> {
        match self.loc {
            GenericLocation::Flag(f) => Ok(format!("{}_{}", f.output_prf(), self.sub)),
            GenericLocation::MAS(mas) => Ok(format!("{}_{}", mas.output_prf(), self.sub)),
            GenericLocation::Register(r) => Ok(format!("{}_{}", r.output_prf(), self.sub)),
            GenericLocation::Memory(_) => Ok(format!("mem_{}", self.sub)),
            #[cfg(not(feature = "stack_func"))]
            GenericLocation::Stack(s) => Ok(format!("stack_{}_{}", s.offset, self.sub)),
            #[cfg(feature = "stack_func")]
            GenericLocation::Stack(s) => Ok(format!("(stack {} {})", s.offset, self.sub)),
        }
    }
}

impl_Sym2Smt!(LocationSub);

impl<L, T> StringifyExpr for GenericAssignment<L, T>
where
    L: StringifySym + LHSValue,
    GenericExpr<T>: StringifyExpr + RHSValue,
{
    fn stringify_expr(&self) -> Result<String> {
        Ok(format!(
            "(= {} {})",
            self.lhs.stringify_sym()?,
            self.rhs.stringify_expr()?
        ))
    }
}

// impl_Expr2Smt!(GenericAssignment<L: StringifySym, R: StringifyExpr>);

impl<L: StringifySym + LHSValue, T> Expr2Smt for GenericAssignment<L, T>
where
    GenericExpr<T>: RHSValue + StringifyExpr,
{
    fn expr_to_smt2<Writer: std::io::Write>(&self, w: &mut Writer, _: ()) -> rsmt2::SmtRes<()> {
        w.write(self.stringify_expr().unwrap().as_bytes())?;
        Ok(())
    }
}

impl<T> StringifyExpr for GenericExpr<T>
where
    T: StringifySym,
{
    fn stringify_expr(&self) -> Result<String> {
        match self {
            // TODO: handle different sizes of ANY
            GenericExpr::Any(size) => Ok(format!("any{}", size.size_bits())),
            GenericExpr::Imm(i) => i.stringify_expr(),
            GenericExpr::Var(v) => v.stringify_sym(),
            GenericExpr::Unary(uop, exp) => Ok(format!(
                "({} {})",
                uop.stringify_sym()?,
                exp.stringify_expr()?
            )),
            GenericExpr::Binary(bop, e1, e2) => Ok(format!(
                "({} {} {})",
                bop.stringify_sym()?,
                e1.stringify_expr()?,
                e2.stringify_expr()?
            )),
            GenericExpr::Ite(rel, ethen, eelse) => Ok(format!(
                "(ite {} {} {})",
                rel.stringify_expr()?,
                ethen.stringify_expr()?,
                eelse.stringify_expr()?
            )),
            GenericExpr::Const(c) => c.stringify_sym(),
            GenericExpr::Alias(a) => a.stringify_sym(),
        }
    }
}

impl_Expr2Smt!(GenericExpr<T: StringifySym>);

impl StringifySym for AliasInner {
    fn stringify_sym(&self) -> Result<String> {
        match self {
            AliasInner::Stack(offset) => Ok(format!("stack_{}", offset)),
        }
    }
}

impl StringifySym for Const {
    fn stringify_sym(&self) -> Result<String> {
        Ok(format!("{}", self.name))
    }
}

impl_Sym2Smt!(Const);

impl StringifySym for Alias {
    fn stringify_sym(&self) -> Result<String> {
        #[cfg(not(feature = "stack_func"))]
        match self.sub {
            Some(s) => Ok(format!("{}_{}", self.inner.stringify_sym()?, s)),
            None => Ok(format!("{}", self.inner.stringify_sym()?)),
        }
        #[cfg(feature = "stack_func")]
        match self.inner {
            AliasInner::Stack(offset) => match self.sub {
                Some(s) => Ok(format!(
                    "(stack {} {})",
                    Imm::from(offset as u64).stringify_expr()?,
                    Imm::from(s as u64).stringify_expr()?
                )),
                None => Ok(format!("stack_{}", offset)),
            },
        }
    }
}

impl<T> Sym2Smt for GenericExpr<T>
where
    GenericExpr<T>: StringifySym,
{
    fn sym_to_smt2<Writer: std::io::Write>(&self, w: &mut Writer, _: ()) -> rsmt2::SmtRes<()> {
        w.write(self.stringify_sym().unwrap().as_bytes())?;
        Ok(())
    }
}

impl<T> StringifySym for GenericExpr<T> {
    fn stringify_sym(&self) -> Result<String> {
        match self {
            GenericExpr::Const(c) => Ok(format!("{}", c.name)),
            _ => Err(anyhow!("Non-constant expression cannot be a symbol")),
        }
    }
}

impl<T: Sorted + std::fmt::Debug> Sort2Smt for GenericExpr<T> {
    fn sort_to_smt2<Writer: std::io::Write>(&self, w: &mut Writer) -> rsmt2::SmtRes<()> {
        w.write(self.stringify_sort().unwrap().as_bytes())?;
        Ok(())
    }
}

impl<T: Sorted + std::fmt::Debug> StringifySort for GenericExpr<T> {
    fn stringify_sort(&self) -> Result<String> {
        self.infer_sort()?.stringify_sort()
    }
}

impl<T> StringifyExpr for GenericRelationship<T>
where
    T: StringifySym,
{
    fn stringify_expr(&self) -> Result<String> {
        Ok(format!(
            "({} {} {})",
            self.relationship.stringify_sym()?,
            self.lhs.stringify_expr()?,
            self.rhs.stringify_expr()?
        ))
    }
}

impl_Expr2Smt!(GenericRelationship<T: StringifySym>);

impl StringifyExpr for Imm {
    fn stringify_expr(&self) -> Result<String> {
        // debug!("trying to stringify imm: {:#?}", self);
        match self.size.get_sort() {
            Sort::Bool => match self.value {
                0 => Ok("false".to_string()),
                1 => Ok("true".to_string()),
                _ => Err(anyhow!("Invalid bool value")),
            },
            Sort::BitVec(size) if size == 128 => {
                if self.value > (u32::MAX as u64) {
                }
                Ok(format!("#x{:032x}", self.value as u128))
            }
            Sort::BitVec(size) if size == 64 => Ok(format!("#x{:016x}", self.value)),
            Sort::BitVec(size) if size == 32 => {
                if self.value > (u32::MAX as u64) {
                }
                Ok(format!("#x{:08x}", self.value as u32))
            }
            Sort::BitVec(size) if size == 16 => {
                // TODO: This doesn't seem right?
                // if self.value > (i16::MAX as u64) || self.value < (i16::MIN as u64) {
                if self.value > (u16::MAX as u64) {
                    Err(anyhow!("Imm value exceeds 16-bit range"))
                } else {
                    Ok(format!("#x{:04x}", self.value))
                }
            }
            Sort::BitVec(size) if size == 8 => {
                // if self.value > (i8::MAX as u64) || self.value < (i8::MIN as u64) {
                if self.value > (u8::MAX as u64) {
                    Err(anyhow!("Imm value exceeds 8-bit range"))
                } else {
                    Ok(format!("#x{:02x}", self.value))
                }
            }
            Sort::BitVec(size) => Err(anyhow!("BitVec size {} not supported", size)),
        }
    }
}
