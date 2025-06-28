#![feature(string_remove_matches)]

pub mod ast;
pub mod prf;
pub mod smt;
mod ssa;
pub mod traits;
pub mod typer;
pub mod utils;

pub use ast::*;
pub use prf::OutputPrf;
pub use ssa::*;
pub use traits::*;
pub use typer::*;
pub use utils::*;

use iced_asm::UsedMemory;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParsingError {
    #[error("Unrecognized unary operator {:?}", .0)]
    UnaryOp(String),
    #[error("Unrecognized binary operator {:?}", .0)]
    BinaryOp(String),
    #[error("Unrecognized boolean unary operator {:?}", .0)]
    BooleanUnaryOp(String),
    #[error("Unrecognized boolean binary operator {:?}", .0)]
    BooleanBinaryOp(String),
    #[error("Unrecognized value size in {:?}", .0)]
    ValSize(String),
    #[error("Unrecognized location {:?}", .0)]
    Location(String),
    #[error("Unrecognized flag {:?}", .0)]
    Flag(String),
    #[error("Unrecognized register {:?}", .0)]
    Register(String),
    #[error("Unrecognized binary arithmetic operator {:?}", .0)]
    BVBinaryArith(String),
    #[error("Unrecognized binary relation operator {:?}", .0)]
    BVBinaryRelation(String),
    #[error("Unrecognized flag {:?}", .0)]
    Flags(String),
    #[error("Unrecognized MicroArchitecturalState {:?}", .0)]
    MicroArchitecturalState(String),
}

#[derive(Debug, Error)]
pub enum ConversionError {
    #[error("Unsupported UsedMemory {:?}", .0)]
    UsedMemory2MemCell(UsedMemory),
}

#[derive(Debug, Clone, Error)]
pub enum AstConvertionError {
    #[error("Failed converting a location to memory location from {:?}", .0)]
    LocationToMemCell(Location),
}
