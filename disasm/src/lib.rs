pub mod cfg;
pub mod dis;
pub use cfg::*;
pub use dis::*;
use iced_x86::Instruction;
use std::collections::{BTreeMap, HashMap};

type Disassembled = BTreeMap<u64, Instruction>;

pub struct SymInfo {
    pub addr: u64,
    pub size: u64,
    pub data: Vec<u8>,
}

type SymbolMap = HashMap<String, SymInfo>;
