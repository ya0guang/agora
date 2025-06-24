use anyhow::{anyhow, Result};
use iced_asm::{
    Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, SymbolResolver,
    SymbolResult,
};
use log::{debug, error, trace, warn};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use petgraph::graphmap::GraphMap;
use petgraph::Directed;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

pub type Disassembled = BTreeMap<u64, Instruction>;

#[derive(Default, Debug)]
pub struct BasicBlock {
    /// The address of the first instruction in the block
    pub start: u64,
    /// The address of the last instruction in a basic block (not the end of the last instruction!)
    pub end: u64,
}

pub struct MySymbolResolver {
    pub map: HashMap<u64, String>,
}

pub struct SymInfo {
    pub addr: u64,
    pub size: u64,
    pub data: Vec<u8>,
}

type SymbolMap = HashMap<String, SymInfo>;

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

#[derive(Debug)]
pub struct ControlFlowInfo {
    pub basic_blocks: BTreeMap<u64, BasicBlock>,
    pub control_flow_graph: GraphMap<u64, (), Directed>,
}

impl ControlFlowInfo {
    pub fn first_ins_addr(&self) -> u64 {
        *self.basic_blocks.first_key_value().unwrap().0
    }
}

pub fn cfg_analysis(raw: &[u8], dis: &Disassembled) -> Result<ControlFlowInfo> {
    let bbs = build_bbs(raw, dis)?;
    let cfg = build_cfg(raw, dis, &bbs)?;
    Ok(ControlFlowInfo {
        basic_blocks: bbs,
        control_flow_graph: cfg,
    })
}

pub fn build_cfg(
    raw: &[u8],
    dis: &Disassembled,
    bbs: &BTreeMap<u64, BasicBlock>,
) -> Result<GraphMap<u64, (), Directed>> {
    let mut cfg: GraphMap<u64, (), petgraph::Directed> = GraphMap::new();
    let first_addr = dis.first_key_value().unwrap().0;
    for (addr, ins) in dis {
        match ins.flow_control() {
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
                // If next instruction is in another bb, add an edge
                let next_addr = addr + ins.len() as u64;
                if let Some(_next_bb) = bbs.get(&next_addr) {
                    debug!(
                        "sequential control flow bridges different bbs at 0x{:x} to 0x{:x}",
                        addr, next_addr
                    );
                    let current_bb_key = find_site_bb(&bbs, *addr)?;
                    cfg.add_edge(current_bb_key, next_addr, ());
                }
            }
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                let target_addr = get_branch_target(ins);
                let current_bb_key = find_site_bb(&bbs, *addr)?;
                cfg.add_edge(current_bb_key, target_addr, ());
                // avoid adding an edge if the branch is unconditional
                if let FlowControl::ConditionalBranch = ins.flow_control() {
                    let next_addr = find_site_bb(bbs, addr + ins.len() as u64)?;
                    cfg.add_edge(current_bb_key, next_addr, ());
                }
            }
            FlowControl::IndirectBranch => {
                let current_bb_key = find_site_bb(&bbs, *addr)?;
                let table_size = get_indirect_jump_tablesize(dis.range(..addr + 1));
                debug!(
                    "Indirect control flow detected at {:x}, table size: {}",
                    addr, table_size
                );
                let table_start_offset = ins.next_ip() - first_addr;
                let offsets = get_offsets(
                    &raw[table_start_offset as usize
                        ..(table_start_offset + table_size * 4) as usize],
                );
                for offset in offsets {
                    let target = u64::try_from(ins.next_ip() as i64 + offset as i64)?;
                    cfg.add_edge(current_bb_key, target, ());
                }
            }
            FlowControl::Return
            | FlowControl::Exception
            | FlowControl::XbeginXabortXend
            | FlowControl::Interrupt => {}
        }
    }
    warn!("CFG: {:#x?}", cfg);
    Ok(cfg)
}

pub fn build_bbs(raw: &[u8], dis: &Disassembled) -> Result<BTreeMap<u64, BasicBlock>> {
    debug!("Analyzing function cfg");
    // (block start address -> BasicBlock)
    let mut bbs = BTreeMap::new();
    let first_addr = dis.first_key_value().unwrap().0;
    // the nodes of the cfg are block start addresses
    let original_bb = BasicBlock {
        start: dis
            .first_key_value()
            .ok_or(anyhow!("No instruction found in the disassembly"))?
            .1
            .ip(),
        end: *dis
            .last_key_value()
            .ok_or(anyhow!("No instruction found in the disassembly"))?
            .0,
    };

    bbs.insert(original_bb.start, original_bb);
    trace!("Beginning of analysis: Basic blocks: {:x?}", bbs);

    for (addr, ins) in dis {
        trace!(
            "Analyzing instruction: {:?} @ 0x{:x}, {:?}, mnemonic: {:?}",
            ins,
            addr,
            ins.flow_control(),
            ins.mnemonic()
        );
        match ins.flow_control() {
            // Block continues
            FlowControl::Next | FlowControl::Call => {}
            FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
                split(&mut bbs, *addr, ins.len() as u64)?;
                let target = get_branch_target(ins);
                let target_prev = *dis.range(..target).last().unwrap().0;
                split(
                    &mut bbs,
                    target_prev,
                    dis.get(&target_prev).unwrap().len() as u64,
                )?;
            }
            FlowControl::IndirectCall => {
                warn!("Indirect control flow detected at {:x}", addr)
            }
            FlowControl::IndirectBranch => {
                // including addr itself in range
                let table_size = get_indirect_jump_tablesize(dis.range(..addr + 1));
                debug!(
                    "Indirect control flow detected at {:x}, table size: {}",
                    addr, table_size
                );
                let table_start_offset = ins.next_ip() - first_addr;
                let offsets = get_offsets(
                    &raw[table_start_offset as usize
                        ..(table_start_offset + table_size * 4) as usize],
                );
                warn!("offsets: {:?}", offsets);
                // add a dummy BB for the switch table
                split(&mut bbs, ins.next_ip() + (table_size - 1) * 4, 4)?;
                for offset in offsets {
                    let target = u64::try_from(ins.next_ip() as i64 + offset as i64)?;
                    let target_prev = *dis.range(..target).last().unwrap().0;
                    warn!("target address: {:x}", target);
                    split(
                        &mut bbs,
                        target_prev,
                        dis.get(&target_prev).unwrap().len() as u64,
                    )?;
                }
            }
            FlowControl::XbeginXabortXend | FlowControl::Interrupt => {
                error!("Unexpected control flow at {:x}, {:x?}", addr, ins);
            }
            // ud2 is considered exception, and usually presented after return
            // Block ends when seeing these instructions
            FlowControl::Return | FlowControl::Exception => {
                split(&mut bbs, *addr, ins.len() as u64)?;
            }
        }
    }
    warn!("Basic blocks: {:x?}", bbs);
    Ok(bbs)
}

fn get_branch_target(ins: &Instruction) -> u64 {
    let target = ins.near_branch_target();
    if target == 0 {
        panic!("problematic branch target: {:?}", ins);
    }
    target
}

/// Split the basic block at the given address
/// A new block will be added from (site + site_ins_len) to previous end
/// The key for the added basic block is returned
fn split(bbs: &mut BTreeMap<u64, BasicBlock>, site: u64, site_ins_length: u64) -> Result<u64> {
    let bb_key_to_split = find_site_bb(bbs, site)?;
    match bbs.get_mut(&bb_key_to_split) {
        Some(prev_bb) => {
            if site == prev_bb.end {
                debug!("really no need to split @ 0x{:x}", site);
                return Ok(site);
            }
            debug!(
                "Splitting block: 0x{:x?} at 0x{:x} with length {}",
                bb_key_to_split, site, site_ins_length
            );
            let new_bb = BasicBlock {
                start: site + site_ins_length,
                end: prev_bb.end,
            };
            let result = new_bb.start;
            assert!(new_bb.end >= new_bb.start);
            prev_bb.end = site;
            bbs.insert(new_bb.start, new_bb);
            debug!("Splitting done, blocks: {:x?}", bbs);
            return Ok(result);
        }
        None => {
            panic!("Basic block not found at 0x{:x}", bb_key_to_split);
        }
    }
}

pub fn find_site_bb(bbs: &BTreeMap<u64, BasicBlock>, site_addr: u64) -> Result<u64> {
    // target + 1 since the upper bound is exclusive
    let results = bbs.range(..(site_addr + 1));
    let site = results.last().ok_or(anyhow!(
        "No split site found for target address 0x{:x}",
        site_addr
    ))?;
    if (site.1.end < site_addr) || (site.1.start > site_addr) {
        return Err(anyhow!(
            "incorrect split site found at addr: 0x{:x}",
            site_addr
        ));
    }
    Ok(*site.0)
}

// TODO: remove the duplication
pub fn get_indirect_jump_tablesize<'a, T>(dis: T) -> u64
where
    T: Iterator<Item = (&'a u64, &'a Instruction)> + DoubleEndedIterator,
{
    let last_eight = dis.rev().take(8).collect::<Vec<_>>();
    // warn!("last_seven: {:#x?}", last_eight);
    assert!(
        last_eight.len() == 8,
        "Not enough instructions to resolve indirect branch"
    );
    // instruction 0: indirect jump
    assert!(
        last_eight[0].1.mnemonic() == Mnemonic::Jmp,
        "Expected indirect jump instruction"
    );
    // instruction -1: add {table_base_reg} {offset_reg}
    assert!(
        last_eight[1].1.op0_kind() == OpKind::Register,
        "Expected register operand"
    );
    assert!(
        last_eight[1].1.op1_kind() == OpKind::Register,
        "Expected register operand"
    );
    assert!(
        last_eight[1].1.mnemonic() == Mnemonic::Add,
        "Expected add instruction"
    );
    let table_base_reg = last_eight[1].1.op0_register();
    let offset_reg = last_eight[1].1.op1_register();
    // instruction -2: movsd {table_offset_reg} {table_offset}
    assert!(
        last_eight[2].1.op0_kind() == OpKind::Register,
        "Expected register operand"
    );
    assert!(
        last_eight[2].1.op0_register() == offset_reg,
        "equal register operand as offset_reg"
    );
    assert!(
        last_eight[2].1.mnemonic() == Mnemonic::Movsxd,
        "Expected add instruction"
    );
    // instruction -3: lea {table_base_reg} {table_base}
    // table_base should usually usually be the next_rip of the jmp instruction
    assert!(
        last_eight[3].1.op0_kind() == OpKind::Register,
        "Expected register operand"
    );
    assert!(
        last_eight[3].1.op0_register() == table_base_reg,
        "equal register operand as table_base_reg"
    );
    assert!(
        last_eight[3].1.mnemonic() == Mnemonic::Lea,
        "Expected lea instruction"
    );
    // instruction -4: mov
    // instruction -5: jae default case
    // instruction -6: cmp {index_reg} {table_size}
    // Sometimes: instruction -7: mov {index_reg} {table_size}
    let table_size = if last_eight[6].1.mnemonic() == Mnemonic::Cmp {
        last_eight[6].1.immediate(1)
    } else {
        assert!(
            last_eight[7].1.mnemonic() == Mnemonic::Cmp,
            "Expected cmp instruction"
        );
        last_eight[7].1.immediate(1)
    };
    debug!("table_size: {}", table_size);
    assert!(table_size > 0, "Table size should be greater than 0");
    return table_size;
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

// pub fn get_indirect_jump_tablesize<'a, T>(dis: T) -> i32
// where
//     T: Iterator<Item = (&'a u64, &'a Instruction)> + DoubleEndedIterator,
// {
//     let last_seven = dis.rev().take(8).collect::<Vec<_>>();
//     for i in last_seven.iter() {
//         debug!("0x{:x}: {}", i.0, i.1);
//     }
//     assert!(
//         last_seven.len() == 8,
//         "Not enough instructions to resolve indirect branch"
//     );
//     // instruction 0: indirect jump
//     assert!(
//         last_seven[0].1.mnemonic() == Mnemonic::Jmp,
//         "Expected indirect jump instruction"
//     );
//     // instruction -1: add {table_base_reg} {offset_reg}
//     assert!(
//         last_seven[1].1.op0_kind() == OpKind::Register,
//         "Expected register operand"
//     );
//     assert!(
//         last_seven[1].1.op1_kind() == OpKind::Register,
//         "Expected register operand"
//     );
//     assert!(
//         last_seven[1].1.mnemonic() == Mnemonic::Add,
//         "Expected add instruction"
//     );
//     let table_base_reg = last_seven[1].1.op0_register();
//     let offset_reg = last_seven[1].1.op1_register();
//     // instruction -2: movsd {table_offset_reg} {table_offset}
//     assert!(
//         last_seven[2].1.op0_kind() == OpKind::Register,
//         "Expected register operand"
//     );
//     assert!(
//         last_seven[2].1.op0_register() == offset_reg,
//         "equal register operand as offset_reg"
//     );
//     assert!(
//         last_seven[2].1.mnemonic() == Mnemonic::Movsxd,
//         "Expected add instruction"
//     );
//     // instruction -3: lea {table_base_reg} {table_base}
//     // table_base should usually usually be the next_rip of the jmp instruction
//     assert!(
//         last_seven[3].1.op0_kind() == OpKind::Register,
//         "Expected register operand"
//     );
//     assert!(
//         last_seven[3].1.op0_register() == table_base_reg,
//         "equal register operand as table_base_reg"
//     );
//     assert!(
//         last_seven[3].1.mnemonic() == Mnemonic::Lea,
//         "Expected lea instruction"
//     );
//     // instruction -4: mov
//     // instruction -5: jae default case
//     // instruction -6: cmp {index_reg} {table_size}
//     // Sometimes: instruction -7: mov {index_reg} {table_size}
//     let table_size = if last_seven[6].1.mnemonic() == Mnemonic::Cmp {
//         last_seven[6].1.immediate(1)
//     } else {
//         assert!(
//             last_seven[7].1.mnemonic() == Mnemonic::Cmp,
//             "Expected cmp instruction"
//         );
//         last_seven[7].1.immediate(1)
//     };
//     debug!("table_size: {}", table_size);
//     assert!(table_size > 0, "Table size should be greater than 0");
//     return table_size as _;
// }

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
    use iced_asm::FastFormatter;

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
