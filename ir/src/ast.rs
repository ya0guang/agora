// The ast of Proof
// Part of the code is from VeriWASM IR.

use crate::prf::OutputPrf;
use crate::typer::Sort;
use crate::{traits::*, Subscript};
use crate::{
    AstConvertionError, ConversionError, LocationSub, ParsingError, SSExpr, SortInfer, Sorted,
    SubRegister,
};
use anyhow::{anyhow, Result};
use iced_asm::{Register, UsedMemory};
use std::collections::HashSet;
use std::convert::{From, TryFrom};
use std::default;
use std::fmt::Write;
use std::hash::Hash;

pub trait LocationType {
    fn is_memory(&self) -> bool;

    fn is_register(&self) -> bool;

    fn is_flag(&self) -> bool;
}

// impl From<Register> for Location {
//     fn from(item: Register) -> Location {
//         Location::Register(item)
//     }
// }

impl From<MemCell> for Location {
    fn from(value: MemCell) -> Self {
        Location::Memory(value)
    }
}

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum Proof {
    Asgn(Assignment),
    Rel(Relationship),
    Hint(String, Option<Relationship>),
    Anno(Annotation),
}

impl TryInto<Assignment> for Proof {
    type Error = anyhow::Error;
    fn try_into(self) -> Result<Assignment> {
        match self {
            Proof::Asgn(a) => Ok(a),
            _ => Err(anyhow!("Not an assignment")),
        }
    }
}

// #[derive(Debug, PartialEq, Clone, Hash, Eq)]
// pub struct GenericAssignment<T> {
//     pub left_hand_side: T,
//     pub right_hand_side: GenericExpr<T>,
// }

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub struct GenericAssignment<L, T>
where
    L: LHSValue + Sized,
    GenericExpr<T>: RHSValue,
{
    pub lhs: L,
    pub rhs: GenericExpr<T>,
}

impl<L, T> GenericAssignment<L, T>
where
    L: LHSValue + Sized,
    GenericExpr<T>: RHSValue,
{
    pub fn new(left_hand_side: L, right_hand_side: GenericExpr<T>) -> Self {
        Self {
            lhs: left_hand_side,
            rhs: right_hand_side,
        }
    }
}

pub type Assignment = GenericAssignment<Location, Location>;

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct GenericRelationship<T> {
    pub relationship: BinaryOp,
    pub lhs: GenericExpr<T>,
    pub rhs: GenericExpr<T>,
}

pub type Relationship = GenericRelationship<Location>;

// TODO: Inverse the relationship to implement the PartialEq
// impl<T> PartialEq for GenericRelationship<T>
// where
//     T: PartialEq,
// {
//     // some relationship communative if we inverse the relationship
//     fn eq(&self, other: &Self) -> bool {
//         (self.relationship == other.relationship
//             && self.left_hand_side == other.left_hand_side
//             && self.right_hand_side == other.right_hand_side)
//             || (self.relationship == other.relationship.inverse()
//                 && self.left_hand_side == other.right_hand_side
//                 && self.right_hand_side == other.left_hand_side)
//     }
// }

#[macro_export]
macro_rules! rel {
    ($e1: expr, $bin_op:expr, $e2:expr) => {
        GenericRelationship {
            relationship: BinaryOp::try_from($bin_op).unwrap(),
            lhs: $e1,
            rhs: $e2,
        }
    };
}

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum Annotation {
    Inv(AnnotationInvariant),
    Branch(AnnotationBranch),
}

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum AnnotationInvariant {
    ExprInv(Expr),
    RelInv(Relationship),
}

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub struct AnnotationBranch {
    pub label: String,
    pub condition: Relationship,
}

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub struct Const {
    pub sort: Sort,
    pub name: String,
}

impl Const {
    pub fn new(sort: Sort, name: String) -> Const {
        Const { sort, name }
    }
}

#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum GenericExpr<T> {
    Alias(Alias),
    Const(Const),
    Any(ValSize),
    Var(T),
    Imm(Imm),
    Unary(UnaryOp, Box<Self>),
    Binary(BinaryOp, Box<Self>, Box<Self>),
    Ite(Box<Self>, Box<Self>, Box<Self>),
}

#[macro_export]
macro_rules! expr {
    ($e1: expr, $bin_op:expr, $e2:expr) => {
        GenericExpr::Binary(
            BinaryOp::try_from($bin_op).unwrap(),
            Box::new($e1),
            Box::new($e2),
        )
    }; // ($uno_op:expr, $e:expr) => {
       //     GenericExpr::Unary(UnaryOp::try_from($uno_op).unwrap(), Box::new($e))
       // };
       // ($e:expr) => {
       //     GenericExpr::from($e)
       // };
}

impl<T> From<Imm> for GenericExpr<T> {
    fn from(value: Imm) -> GenericExpr<T> {
        GenericExpr::Imm(value)
    }
}

impl<T> From<Alias> for GenericExpr<T> {
    fn from(value: Alias) -> GenericExpr<T> {
        GenericExpr::Alias(value)
    }
}

impl<T> From<Const> for GenericExpr<T> {
    fn from(value: Const) -> GenericExpr<T> {
        GenericExpr::Const(value)
    }
}

impl<T: RegisterTrait + Copy> From<GenericLocation<T>> for GenericExpr<GenericLocation<T>> {
    fn from(value: GenericLocation<T>) -> GenericExpr<GenericLocation<T>> {
        GenericExpr::Var(value)
    }
}

impl From<LocationSub> for GenericExpr<LocationSub> {
    fn from(value: LocationSub) -> GenericExpr<LocationSub> {
        GenericExpr::Var(value)
    }
}

impl<T> From<GenericRelationship<T>> for GenericExpr<T> {
    fn from(value: GenericRelationship<T>) -> GenericExpr<T> {
        GenericExpr::Binary(value.relationship, Box::new(value.lhs), Box::new(value.rhs))
    }
}

impl<T> GenericExpr<T>
where
    T: Clone + Eq + Hash,
    GenericExpr<T>: SortInfer,
{
    pub fn negate(&self) -> GenericExpr<T> {
        assert!(
            self.infer_sort().unwrap() == Sort::Bool,
            "not a boolean expression!"
        );
        GenericExpr::Unary(
            UnaryOp::Boolean(BooleanUnaryOp::Not),
            Box::new(self.clone()),
        )
    }

    /// strip the expression to a variable if it is a variable
    pub fn strip_as_var(&self) -> Result<T> {
        match self {
            GenericExpr::Var(v) => Ok(v.clone()),
            _ => Err(anyhow!("not a variable")),
        }
    }

    /// Get all used variables in the expression
    pub fn used_vars(&self, predicate: fn(&T) -> bool) -> HashSet<T> {
        let mut res = HashSet::new();
        match self {
            GenericExpr::Const(_)
            | GenericExpr::Any(_)
            | GenericExpr::Imm(_)
            | GenericExpr::Alias(_) => {}
            GenericExpr::Var(v) => {
                if predicate(v) {
                    res.insert(v.clone());
                }
            }
            GenericExpr::Unary(_, e) => res.extend(e.used_vars(predicate)),
            GenericExpr::Binary(_, e1, e2) => {
                res.extend(e1.used_vars(predicate));
                res.extend(e2.used_vars(predicate));
            }
            GenericExpr::Ite(eif, ethen, eelse) => {
                // will e1 be considered here?
                res.extend(eif.used_vars(predicate));
                res.extend(ethen.used_vars(predicate));
                res.extend(eelse.used_vars(predicate));
            }
        }
        res
    }
}

// (BV any)
// declear any_1 bool
// ZF_X := any_1

pub type Expr = GenericExpr<Location>;

#[macro_export]
macro_rules! implement_struct {
    ($struct_name:ident, $($enum_val: ident => $s: expr, )+) => {
        #[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
        pub enum $struct_name {
            $($enum_val,)+
        }

        impl OutputPrf for $struct_name {
            fn output_prf(&self) -> String {
                match self {
                    $($struct_name::$enum_val => $s.to_string(),)+
                }
            }
        }

        impl TryFrom<&str> for $struct_name {
            type Error = ParsingError;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                match s {
                    $($s => Ok($struct_name::$enum_val),)+
                    _ => Err(ParsingError::$struct_name(s.to_string())),
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub enum UnaryOp {
    Boolean(BooleanUnaryOp),
    BV(BVUnaryOp),
}

implement_struct!(BooleanUnaryOp,
    Not => "not",
);

#[derive(Debug, PartialEq, Clone, Eq, Hash, PartialOrd, Ord)]
pub enum BVUnaryOp {
    Neg,
    Not,
    ZExtend(usize),
    Extract(usize),
    // This should only appear later in the pipeline after memory is resolved
    Memory(String),
}

impl OutputPrf for BVUnaryOp {
    fn output_prf(&self) -> String {
        match self {
            BVUnaryOp::Neg => "bvneg".to_string(),
            BVUnaryOp::Not => "bvnot".to_string(),
            BVUnaryOp::ZExtend(i) => format!("(_ zero_extend {})", i),
            BVUnaryOp::Extract(i) => format!("(_ extract {} 0)", i),
            BVUnaryOp::Memory(s) => s.to_string(),
        }
    }
}

impl TryFrom<&str> for BVUnaryOp {
    type Error = ParsingError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "bvnot" => Ok(BVUnaryOp::Not),
            "bvneg" => Ok(BVUnaryOp::Neg),
            s if s.starts_with("(zero_extend ") => {
                let mut op = s.to_string();
                op.remove_matches("(zero_extend ");
                op.remove_matches(")");
                op.remove_matches(" ");
                let i = op.parse::<u32>().unwrap();
                Ok(BVUnaryOp::ZExtend(i as _))
            }
            s if s.starts_with("(extract ") => {
                let mut op = s.to_string();
                op.remove_matches("(extract ");
                op.remove_matches(" 0)");
                let i = op.parse::<u32>().unwrap();
                Ok(BVUnaryOp::Extract(i as _))
            }
            _ => Err(ParsingError::UnaryOp(s.to_string())),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub enum BinaryOp {
    Boolean(BooleanBinaryOp),
    BV(BVBinaryOp),
}

#[macro_export]
macro_rules! bv {
    { $op: expr } => {
        BinaryOp::BV(BVBinaryOp::try_from($op).unwrap())
    }
}

#[macro_export]
macro_rules! boolean {
    { $op: expr } => {
        BinaryOp::Boolean(BooleanBinaryOp::try_from($op).unwrap())
    }
}

implement_struct!(BooleanBinaryOp,
    Or => "or",
    And => "and",
    Xor => "xor",
    Implies => "=>",
    Neq => "distinct",
    Eq => "=",
);

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub enum BVBinaryOp {
    Arith(BVBinaryArith),
    Relation(BVBinaryRelation),
}

impl TryFrom<&str> for BVBinaryOp {
    type Error = ParsingError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match (BVBinaryArith::try_from(s), BVBinaryRelation::try_from(s)) {
            (Ok(op), Err(_)) => Ok(BVBinaryOp::Arith(op)),
            (Err(_), Ok(op)) => Ok(BVBinaryOp::Relation(op)),
            (Err(_), Err(_)) | (Ok(_), Ok(_)) => Err(ParsingError::BinaryOp(s.to_string())),
        }
    }
}

implement_struct!(BVBinaryArith,
    Add => "bvadd",
    Sub => "bvsub",
    Mul => "bvmul",
    Div => "bvdiv",
    Mod => "bvrem",
    And => "bvand",
    Or => "bvor",
    Xor => "bvxor",
    Shl => "bvshl",
    Shr => "bvshr",
);

implement_struct!(BVBinaryRelation,
    Eq => "=",
    Neq => "distinct",
    Ult => "bvult",
    Ugt => "bvugt",
    Ule => "bvule",
    Uge => "bvuge",
);

// #[allow(dead_code)]
// impl BVBinaryRelation {
//     fn inverse(&self) -> BVBinaryRelation {
//         match self {
//             BVBinaryRelation::Eq => BVBinaryRelation::Eq,
//             BVBinaryRelation::Neq => BVBinaryRelation::Neq,
//             BVBinaryRelation::Ult => BVBinaryRelation::Uge,
//             BVBinaryRelation::Ule => BVBinaryRelation::Ugt,
//             BVBinaryRelation::Ugt => BVBinaryRelation::Ule,
//             BVBinaryRelation::Uge => BVBinaryRelation::Ult,
//         }
//     }
// }

implement_struct!(ValSize,
    Size1 => "1",
    Size8 => "b",
    Size16 => "w",
    Size32 => "d",
    Size64 => "q",
    // floating point stack register size
    Size80 => "s",
    Size128 => "x",
    Size256 => "y",
    Size512 => "z",
);

impl From<Sort> for ValSize {
    fn from(sort: Sort) -> Self {
        match sort {
            Sort::Bool => ValSize::Size1,
            Sort::BitVec(size) => ValSize::try_from(size / 8).unwrap(),
        }
    }
}

impl ValSize {
    pub fn size_bits(&self) -> usize {
        match self {
            ValSize::Size1 => 1,
            ValSize::Size8 => 8,
            ValSize::Size16 => 16,
            ValSize::Size32 => 32,
            ValSize::Size64 => 64,
            ValSize::Size80 => 80,
            ValSize::Size128 => 128,
            ValSize::Size256 => 256,
            ValSize::Size512 => 512,
        }
    }

    pub fn size_bytes(&self) -> usize {
        self.size_bits() / 8
    }
}

impl default::Default for ValSize {
    fn default() -> Self {
        ValSize::Size64
    }
}

/// in bytes
impl TryFrom<usize> for ValSize {
    type Error = ParsingError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ValSize::Size8),
            2 => Ok(ValSize::Size16),
            4 => Ok(ValSize::Size32),
            8 => Ok(ValSize::Size64),
            10 => Ok(ValSize::Size80),
            16 => Ok(ValSize::Size128),
            32 => Ok(ValSize::Size256),
            64 => Ok(ValSize::Size512),
            ud => Err(ParsingError::ValSize(ud.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Left hand side value
pub enum GenericLocation<T>
where
    GenericMemCell<T>: Copy,
    T: RegisterTrait,
{
    Flag(Flags),
    Register(Register),
    Memory(GenericMemCell<T>),
    MAS(MicroArchitecturalState),
    // Stack is an alias for memory and it should not appear before SSA and in proof.
    // In the future, we should substitute it with a `Alias` struct and make `Alias` valid in SMT
    Stack(Stack),
}

// #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
// pub enum ContraintLocation<T>
// where
//     GenericMemCell<T>: Copy,
//     T: RegisterTrait,
// {
//     Flag(Flags),
//     Register(Register),
//     Memory(GenericMemCell<T>),
//     // Stack is an alias for memory and it should not appear before SSA and in proof.
//     // In the future, we should substitute it with a `Alias` struct and make `Alias` valid in SMT
//     Sized(VSize<Alias>),
// }

impl<T: Copy + RegisterTrait> From<Register> for GenericLocation<T> {
    fn from(reg: Register) -> Self {
        GenericLocation::Register(reg)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AliasInner {
    Stack(i64), // stack offset
}

impl AliasInner {
    pub fn stack(offset: i64) -> Self {
        AliasInner::Stack(offset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Alias {
    pub inner: AliasInner,
    pub size: ValSize,
    pub sub: Option<Subscript>,
}

impl Alias {
    pub fn new(inner: AliasInner, size: ValSize, sub: Option<Subscript>) -> Self {
        Alias { inner, size, sub }
    }
}

// Maybe to create a stack alias resolver?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Stack {
    pub offset: i64,
    pub size: ValSize,
}

impl<T: RegisterTrait + Copy> GenericLocation<T>
where
    GenericMemCell<T>: Clone,
{
    pub fn try_take_memcell(&self) -> Result<GenericMemCell<T>> {
        match self {
            GenericLocation::Memory(mem) => Ok(mem.clone()),
            _ => Err(anyhow!("not a memory location")),
        }
    }
}

pub type Location = GenericLocation<Register>;

// impl Into<Expr> for Location {
//     fn into(self) -> Expr {
//         Expr::Var(self)
//     }
// }

impl<T: RegisterTrait + Copy> LocationType for GenericLocation<T> {
    fn is_memory(&self) -> bool {
        match self {
            GenericLocation::Memory(_) => true,
            _ => false,
        }
    }

    fn is_flag(&self) -> bool {
        match self {
            GenericLocation::Flag(_) => true,
            _ => false,
        }
    }

    fn is_register(&self) -> bool {
        match self {
            GenericLocation::Register(_) => true,
            _ => false,
        }
    }
}

// SOMEDAY: move to iced implementation of MemoryOperand?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GenericMemCell<T: RegisterTrait> {
    // The Registers could be None!
    pub base_reg: T,
    pub index_reg: T,
    pub index_scale_negtive: bool,
    pub displacement: i64,
    pub scale: Option<u8>,
    pub size: ValSize,
}

impl GenericMemCell<SubRegister> {
    pub fn is_rsp_ralted(&self) -> bool {
        *self.base_reg.get_loc() == Register::RSP
        // || self.index_reg.0.full_register() == Register::RSP
    }
}

impl GenericMemCell<Register> {
    pub fn is_rsp_ralted(&self) -> bool {
        self.base_reg == Register::RSP
        // || self.index_reg.0.full_register() == Register::RSP
    }
}

// base + (index * scale) + disp

pub type MemCell = GenericMemCell<Register>;

impl<T: RegisterTrait + Copy> GenericMemCell<T>
where
    GenericLocation<T>: From<T>,
{
    pub fn take_address(&self) -> Result<GenericExpr<GenericLocation<T>>> {
        let index_scale_term: Option<GenericExpr<GenericLocation<T>>> = match self.scale {
            None => None,
            Some(s) => Some(expr!(
                GenericExpr::Var(self.index_reg.into()),
                bv!("bvmul"),
                Imm::from(s as u64).into()
            )),
        };
        let base_index_scale_term: Option<GenericExpr<GenericLocation<T>>> =
            match self.base_reg.register() {
                Register::None => index_scale_term,
                _ => match index_scale_term {
                    None => Some(GenericExpr::Var(self.base_reg.into())),
                    Some(i) => Some(expr!(
                        GenericExpr::Var(self.base_reg.into()),
                        bv!("bvadd"),
                        i
                    )),
                },
            };
        let final_term = if self.displacement == 0 {
            base_index_scale_term
        } else {
            match base_index_scale_term {
                None => Some(Imm::from(self.displacement).into()),
                Some(b) => Some(expr!(b, bv!("bvadd"), Imm::from(self.displacement).into())),
            }
        };
        match final_term {
            None => Err(anyhow!("Cannot extract memory address from the cell")),
            Some(t) => Ok(t),
        }
    }
}

impl GenericMemCell<SubRegister> {
    pub fn take_address(&self) -> Result<SSExpr> {
        let index_scale_term: Option<GenericExpr<_>> = match self.scale {
            None => None,
            Some(s) => Some(expr!(
                GenericExpr::Var(self.index_reg.into()),
                bv!("bvmul"),
                Imm::from(s as u64).into()
            )),
        };
        let base_index_scale_term: Option<GenericExpr<_>> = match self.base_reg.register() {
            Register::None => index_scale_term,
            _ => match index_scale_term {
                None => Some(GenericExpr::Var(self.base_reg.into())),
                Some(i) => Some(expr!(
                    GenericExpr::Var(self.base_reg.into()),
                    bv!("bvadd"),
                    i
                )),
            },
        };
        let final_term = if self.displacement == 0 {
            base_index_scale_term
        } else {
            match base_index_scale_term {
                None => Some(GenericExpr::Imm(Imm::from(self.displacement))),
                Some(b) => Some(expr!(b, bv!("bvadd"), Imm::from(self.displacement).into())),
            }
        };
        match final_term {
            None => Err(anyhow!("Cannot extract memory address from the cell")),
            Some(t) => Ok(t),
        }
    }
}

impl TryFrom<UsedMemory> for MemCell {
    type Error = ConversionError;
    fn try_from(value: UsedMemory) -> Result<Self, Self::Error> {
        if value.memory_size().is_packed() {
            return Err(ConversionError::UsedMemory2MemCell(value));
        }
        let mem = MemCellBuilder::new()
            .base_reg(value.base())
            .index_reg(value.index())
            .displacement(value.displacement() as _)
            .scale(Some(value.scale() as _))
            //TODO: unwrap or ConversionError
            .size(ValSize::try_from(value.memory_size().size()).unwrap())
            .build();

        Ok(mem)
    }
}

pub struct MemCellBuilder {
    v: MemCell,
    next_neg: bool,
}

// TODO: handle negative displacement
impl MemCellBuilder {
    pub fn new() -> Self {
        MemCellBuilder {
            v: MemCell {
                base_reg: Register::None,
                index_reg: Register::None,
                index_scale_negtive: false,
                displacement: 0,
                // NOTE: in iced the scale is at least 1!
                scale: None,
                size: ValSize::default(),
            },
            next_neg: false,
        }
    }

    pub fn base_reg(mut self, base_reg: Register) -> Self {
        self.v.base_reg = base_reg;
        self
    }

    pub fn index_reg(mut self, index_reg: Register) -> Self {
        if self.next_neg {
            self.v.index_scale_negtive = true;
        }
        self.v.index_reg = index_reg;
        self
    }

    pub fn displacement(mut self, displacement: i64) -> Self {
        if self.next_neg {
            self.v.displacement = -displacement;
            self.next_neg = false;
        } else {
            self.v.displacement = displacement;
        }
        self
    }

    pub fn next_negtivity(mut self, neg: bool) -> Self {
        self.next_neg = neg;
        self
    }

    pub fn scale(mut self, scale: Option<u8>) -> Self {
        match scale {
            Some(scale) => {
                if scale == 1 || scale == 2 || scale == 4 || scale == 8 {
                    self.v.scale = Some(scale);
                } else {
                    panic!("Invalid scale: {}", scale);
                }
            }
            None => self.v.scale = None,
        }
        self
    }

    pub fn size(mut self, size: ValSize) -> Self {
        self.v.size = size;
        self
    }

    pub fn build(mut self) -> MemCell {
        // TODO: check if its valid
        if self.v.index_reg == Register::None {
            self.v.scale = None;
        }
        if self.v.base_reg == Register::None
            && self.v.index_reg == Register::None
            && self.v.displacement == 0
        {
            panic!("Invalid memory cell: {:?}", self.v);
        }
        self.v
    }
}

impl Default for Location {
    fn default() -> Self {
        Location::Register(Register::None)
    }
}

impl TryFrom<&str> for Location {
    type Error = ParsingError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if let Ok(reg) = get_register(s) {
            return Ok(Location::Register(reg));
        }
        if let Ok(flag) = Flags::try_from(s) {
            return Ok(Location::Flag(flag));
        }
        return Err(ParsingError::Location(s.to_string()));
    }
}

impl Location {
    pub fn to_memvar(&self) -> Result<Location, AstConvertionError> {
        match self {
            Location::Flag(_) | Location::Stack(_) | Location::MAS(_) => {
                Err(AstConvertionError::LocationToMemCell(*self))
            }
            Location::Memory(_mem) => Ok(self.clone()),
            Location::Register(reg) => Ok(LocationBuilder::new()
                .memcell(MemCellBuilder::new().base_reg(reg.clone()).build())
                .build()),
        }
    }
}

// TODO: Deprecate LocationBuilder
pub struct LocationBuilder {
    v: Location,
    uninitialized: bool,
}

impl LocationBuilder {
    pub fn new() -> Self {
        LocationBuilder {
            v: Location::default(),
            uninitialized: true,
        }
    }

    pub fn register(mut self, reg: Register) -> Self {
        // WARNING: Register could be None
        self.v = Location::Register(reg);
        self.uninitialized = false;
        self
    }

    pub fn flag(mut self, flag: Flags) -> Self {
        self.v = Location::Flag(flag);
        self.uninitialized = false;
        self
    }

    pub fn mas(mut self, mas: MicroArchitecturalState) -> Self {
        self.v = Location::MAS(mas);
        self.uninitialized = false;
        self
    }

    pub fn memcell(mut self, mem: MemCell) -> Self {
        self.v = Location::Memory(mem);
        self.uninitialized = false;
        self
    }

    pub fn build(self) -> Location {
        if self.uninitialized {
            panic!("LocationBuilder uninitialized");
        }
        self.v
    }
}

#[derive(Debug, Clone, Copy, Hash, Eq)]
pub struct Imm {
    pub value: u64,
    // Do we really need a size on Imm? Yes! For sort checking
    pub size: ValSize,
}

#[macro_export]
macro_rules! imm {
    ($e:expr) => {
        Imm: from($e)
    };
}

impl Imm {
    pub fn new(value: u64, size: ValSize) -> Self {
        Imm { value, size }
    }

    pub fn convert(&self, size: ValSize) -> Self {
        Imm {
            value: self.value,
            size,
        }
    }

    pub fn value(&self) -> i64 {
        self.value as i64
    }
}

impl Sorted for Imm {
    fn get_sort(&self) -> Sort {
        self.size.get_sort()
    }
}

impl PartialEq for Imm {
    fn eq(&self, other: &Imm) -> bool {
        self.value == other.value
    }
}

impl From<u128> for Imm {
    fn from(v: u128) -> Self {
        if v > u64::MAX as _ {
            panic!("Number too big {}", v);
        }
        Imm {
            value: v as _,
            size: ValSize::Size128,
        }
    }
}

impl From<u64> for Imm {
    fn from(v: u64) -> Self {
        if v > i64::MAX as u64 {}
        Imm {
            value: v as _,
            size: ValSize::default(),
        }
    }
}

impl From<i64> for Imm {
    fn from(v: i64) -> Self {
        Imm {
            value: v as _,
            size: ValSize::default(),
        }
    }
}

impl From<i32> for Imm {
    fn from(v: i32) -> Self {
        Imm {
            value: v as _,
            size: ValSize::Size32,
        }
    }
}

impl From<u32> for Imm {
    fn from(v: u32) -> Self {
        Imm {
            value: v as _,
            size: ValSize::Size32,
        }
    }
}

impl From<i16> for Imm {
    fn from(v: i16) -> Self {
        Imm {
            value: v as _,
            size: ValSize::Size16,
        }
    }
}

impl From<u16> for Imm {
    fn from(v: u16) -> Self {
        Imm {
            value: v as _,
            size: ValSize::Size16,
        }
    }
}

impl From<i8> for Imm {
    fn from(v: i8) -> Self {
        Imm {
            value: v as _,
            size: ValSize::Size8,
        }
    }
}

impl From<u8> for Imm {
    fn from(v: u8) -> Self {
        Imm {
            value: v as _,
            size: ValSize::Size8,
        }
    }
}

implement_struct!(Flags,
    CF => "CF",
    PF => "PF",
    AF => "AF",
    ZF => "ZF",
    SF => "SF",
    IF => "IF",
    DF => "DF",
    OF => "OF",
);

implement_struct!(MicroArchitecturalState,
    LoadBuffer => "LoadBuffer",
);

// Need to deal with Register
pub fn get_register(s: &str) -> Result<Register> {
    let mut reg_s = String::new();
    let mut reg = Register::None;
    for r in Register::values() {
        reg_s.clear();
        let _ = write!(&mut reg_s, "{:?} ", r);
        if reg_s.to_lowercase().trim().eq_ignore_ascii_case(s) {
            reg = r;
            break;
        }
    }
    if reg.is_gpr() || reg.is_segment_register() || reg.is_ip() || reg.is_xmm() {
        Ok(reg)
    } else {
        Err(anyhow::anyhow!("Register {} is currently not supported", s))
    }
}
