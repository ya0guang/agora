use crate::{Disassembled, SymInfo, SymbolMap};
use anyhow::Result;
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, SymbolResolver,
    SymbolResult,
};
use log::{debug, trace, warn};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

pub struct MySymbolResolver {
    pub map: HashMap<u64, String>,
}

impl SymbolResolver for MySymbolResolver {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult> {
        if let Some(symbol_string) = self.map.get(&address) {
            Some(SymbolResult::with_str(address, symbol_string.as_str()))
        } else {
            None
        }
    }
}

// disassemble all text sections of the file. This is for simple proof checking
pub fn disasm_text(binary: &[u8]) -> Result<Disassembled> {
    let obj_file = object::File::parse(binary)?;

    let mut result = BTreeMap::new();
    for sec in obj_file.sections() {
        if sec.kind() == SectionKind::Text {
            let data = sec.data().unwrap();
            let mut decoder = Decoder::new(64, data, DecoderOptions::NONE);
            decoder.set_ip(sec.address());
            let _ = decoder.set_position(0)?;
            while decoder.can_decode() {
                let instruction = decoder.decode();
                result.insert(decoder.ip() - (instruction.len() as u64), instruction);
            }
        }
    }
    Ok(result)
}

pub fn resolve_text_symbols(binary: &[u8]) -> Result<SymbolMap> {
    let mut result = HashMap::new();
    let obj_file = object::File::parse(binary)?;

    let functions = obj_file
        .symbols()
        .filter(|sym| sym.kind() == SymbolKind::Text);

    // disassemble symbols in Text section(s)
    for sym in functions {
        // println!("Symbol: {:?}", sym);
        let sym_section = match sym.section_index() {
            Some(i) => obj_file.section_by_index(i)?,
            None => continue,
        };
        // println!("Section: {:?}", sym_section);
        let sym_addr = sym.address();
        let sym_size = sym.size();
        // trace!("Disassembling symbol: {:?} @ {:#x}", sym.name(), sym_addr);
        let sym_bin = sym_section
            .data_range(sym_addr, sym_size)?
            .unwrap()
            .to_vec();
        let syminfo = SymInfo {
            addr: sym_addr,
            size: sym_size,
            data: sym_bin,
        };
        result.insert(sym.name().unwrap().to_string(), syminfo);
    }
    Ok(result)
}

// disassmble the functions of the file
pub fn disasm_binary(path: &Path) -> Result<HashMap<String, Disassembled>> {
    let bin_data = fs::read(path)?;
    let obj_file = object::File::parse(&*bin_data)?;

    // resolve symbols
    let mut sym_map = HashMap::<u64, String>::new();
    for sym in obj_file.symbols() {
        if let Ok(name) = sym.name() {
            sym_map.insert(sym.address(), name.to_string());
        }
    }

    let functions = obj_file
        .symbols()
        .filter(|sym| sym.kind() == SymbolKind::Text);

    let mut disassmbled = HashMap::new();

    // disassemble symbols in Text section(s)
    for sym in functions {
        // println!("Symbol: {:?}", sym);
        let sym_section = match sym.section_index() {
            Some(i) => obj_file.section_by_index(i)?,
            None => continue,
        };
        // println!("Section: {:?}", sym_section);
        let sym_addr = sym.address();
        let sym_size = sym.size();
        if sym_size == 0 {
            // TODO: rectify symbol sizes, current size is not accurate!
            continue;
        }
        trace!("Disassembling symbol: {:?} @ {:#x}", sym.name(), sym_addr);
        let sym_bin = sym_section.data_range(sym_addr, sym_size)?.unwrap();

        disassmbled.insert(
            sym.name().unwrap().to_string(),
            disasm_block(sym_bin, sym_addr),
        );
    }

    Ok(disassmbled)
}

pub fn disasm_block(data: &[u8], initial_ip: u64) -> Disassembled {
    debug!("Disassembling function @ {:#x}", initial_ip);
    let mut result = BTreeMap::new();
    let mut pos = initial_ip;
    for i in disasm_code(data, Some(initial_ip)) {
        result.insert(pos, i);
        pos += i.len() as u64;
        match i.flow_control() {
            FlowControl::IndirectBranch => {
                warn!("Indirect branch at {:#x}", pos);
                let table_size = get_indirect_jump_tablesize(result.iter()) as usize;
                let table_start_ip = i.next_ip();
                debug!(
                    "Indirect JMP table size: {}, table starts at {:x}",
                    table_size, table_start_ip
                );
                let skipped_ip = (table_size * 4) as u64 + pos;
                result.extend(disasm_block(
                    &data[(skipped_ip - initial_ip) as usize..],
                    skipped_ip,
                ));
                // let table_data_start = table_start_ip - (initial_ip);
                // let offsets =
                //     get_offsets(&data[table_data_start as usize..(table_data_start as usize + table_size * 4)]);
                // let mut data_slice_indexes = offsets
                //     .iter()
                //     .map(|x| (*x + (table_start_ip - initial_ip) as i32) as u64)
                //     .collect::<Vec<_>>();
                // data_slice_indexes.push(data.len() as _);
                // debug!("data_slice_indexes: {:?}", data_slice_indexes);
                // for i in 0..data_slice_indexes.len() - 1 {
                //     let bb_start = data_slice_indexes[i] + initial_ip;
                //     if bb_start < pos {
                //         continue;
                //     }
                //     // if data_slice_indexes[i] >
                //     result.extend(disasm_block(
                //         &data[data_slice_indexes[i] as usize..data_slice_indexes[i + 1] as usize],
                //         bb_start),
                //     );
                //     debug!("IP for the indirect jump target: {:x}", bb_start);
                // }
                break;
            }
            _ => {}
        }
    }
    result
}

pub fn get_offsets(data: &[u8]) -> BTreeSet<i32> {
    let mut result = BTreeSet::new();
    assert!(data.len() % 4 == 0, "Invalid table size");
    for i in 0..data.len() / 4 {
        let offset = i32::from_le_bytes(data[i * 4..i * 4 + 4].try_into().unwrap());
        result.insert(offset);
    }
    debug!("Offsets: {:?}", result);
    result
}

pub fn get_indirect_jump_tablesize<'a, T>(dis: T) -> i32
where
    T: Iterator<Item = (&'a u64, &'a Instruction)> + DoubleEndedIterator,
{
    let last_seven = dis.rev().take(8).collect::<Vec<_>>();
    for i in last_seven.iter() {
        debug!("0x{:x}: {}", i.0, i.1);
    }
    assert!(
        last_seven.len() == 8,
        "Not enough instructions to resolve indirect branch"
    );
    // instruction 0: indirect jump
    assert!(
        last_seven[0].1.mnemonic() == Mnemonic::Jmp,
        "Expected indirect jump instruction"
    );
    // instruction -1: add {table_base_reg} {offset_reg}
    assert!(
        last_seven[1].1.op0_kind() == OpKind::Register,
        "Expected register operand"
    );
    assert!(
        last_seven[1].1.op1_kind() == OpKind::Register,
        "Expected register operand"
    );
    assert!(
        last_seven[1].1.mnemonic() == Mnemonic::Add,
        "Expected add instruction"
    );
    let table_base_reg = last_seven[1].1.op0_register();
    let offset_reg = last_seven[1].1.op1_register();
    // instruction -2: movsd {table_offset_reg} {table_offset}
    assert!(
        last_seven[2].1.op0_kind() == OpKind::Register,
        "Expected register operand"
    );
    assert!(
        last_seven[2].1.op0_register() == offset_reg,
        "equal register operand as offset_reg"
    );
    assert!(
        last_seven[2].1.mnemonic() == Mnemonic::Movsxd,
        "Expected add instruction"
    );
    // instruction -3: lea {table_base_reg} {table_base}
    // table_base should usually usually be the next_rip of the jmp instruction
    assert!(
        last_seven[3].1.op0_kind() == OpKind::Register,
        "Expected register operand"
    );
    assert!(
        last_seven[3].1.op0_register() == table_base_reg,
        "equal register operand as table_base_reg"
    );
    assert!(
        last_seven[3].1.mnemonic() == Mnemonic::Lea,
        "Expected lea instruction"
    );
    // instruction -4: mov
    // instruction -5: jae default case
    // instruction -6: cmp {index_reg} {table_size}
    // Sometimes: instruction -7: mov {index_reg} {table_size}
    let table_size = if last_seven[6].1.mnemonic() == Mnemonic::Cmp {
        last_seven[6].1.immediate(1)
    } else {
        assert!(
            last_seven[7].1.mnemonic() == Mnemonic::Cmp,
            "Expected cmp instruction"
        );
        last_seven[7].1.immediate(1)
    };
    debug!("table_size: {}", table_size);
    assert!(table_size > 0, "Table size should be greater than 0");
    return table_size as _;
}

pub fn disasm_code(data: &[u8], ip: Option<u64>) -> Vec<Instruction> {
    let mut decoder = match ip {
        Some(ip) => Decoder::with_ip(64, data, ip, DecoderOptions::NONE),
        None => Decoder::new(64, data, DecoderOptions::NONE),
    };
    let insns: Vec<Instruction> = decoder.iter().collect();
    return insns;
}

#[cfg(test)]
mod dis_test {
    use iced_x86::FastFormatter;

    use super::*;

    #[test]
    fn test_func() {
        let mut formatter = FastFormatter::new();
        formatter
            .options_mut()
            .set_space_after_operand_separator(true);
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .try_init();
        let bin_path = Path::new("../resources/spec2006/astar_O0");
        let bin = fs::read(bin_path).unwrap();
        let sym_map = resolve_text_symbols(&bin).unwrap();
        let focused_function = "cos_259";
        let sym_info = sym_map.get(focused_function).unwrap();
        debug!("addr: {}, size: {}", sym_info.addr, sym_info.size);
        let dis = disasm_block(&sym_info.data, sym_info.addr);
        for (addr, ins) in dis {
            let mut output = String::new();
            formatter.format(&ins, &mut output);
            println!("{:#x}: {}", addr, output)
        }
    }

    #[test]
    fn test_bin() {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .try_init();

        let _dis_bin = disasm_binary(Path::new("../resources/spec2006/sjeng_O3")).unwrap();
    }
}
