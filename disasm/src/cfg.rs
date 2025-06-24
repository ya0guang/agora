// use anyhow::{anyhow, Result};
// use iced_x86::{FlowControl, Instruction};
// use log::{debug, error, warn};
// use petgraph::graphmap::GraphMap;
// use petgraph::Directed;
// use std::collections::BTreeMap;
// use crate::Disassembled;

// #[derive(Default, Debug)]
// pub struct BasicBlock {
//     /// The address of the first instruction in the block
//     pub start: u64,
//     /// The address of the last instruction in a basic block (not the end of the last instruction!)
//     pub end: u64,
// }

// #[derive(Debug)]
// pub struct ControlFlowInfo {
//     pub basic_blocks: BTreeMap<u64, BasicBlock>,
//     pub control_flow_graph: GraphMap<u64, (), Directed>,
// }

// impl ControlFlowInfo {
//     pub fn first_ins_addr(&self) -> u64 {
//         *self.basic_blocks.first_key_value().unwrap().0
//     }
// }

// pub fn cfg_analysis(dis: &Disassembled) -> Result<ControlFlowInfo> {
//     let bbs = build_bbs(dis)?;
//     let cfg = build_cfg(dis, &bbs)?;
//     Ok(ControlFlowInfo {
//         basic_blocks: bbs,
//         control_flow_graph: cfg,
//     })
// }

// pub fn build_cfg(
//     dis: &Disassembled,
//     bbs: &BTreeMap<u64, BasicBlock>,
// ) -> Result<GraphMap<u64, (), Directed>> {
//     let mut cfg: GraphMap<u64, (), petgraph::Directed> = GraphMap::new();
//     for (addr, ins) in dis {
//         match ins.flow_control() {
//             FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
//                 // If next instruction is in another bb, add an edge
//                 let next_addr = addr + ins.len() as u64;
//                 if let Some(_next_bb) = bbs.get(&next_addr) {
//                     debug!(
//                         "sequential control flow bridges different bbs at 0x{:x} to 0x{:x}",
//                         addr, next_addr
//                     );
//                     let current_bb_key = find_site_bb(&bbs, *addr)?;
//                     cfg.add_edge(current_bb_key, next_addr, ());
//                 }
//             }
//             FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
//                 let target_addr = get_branch_target(ins);
//                 let current_bb_key = find_site_bb(&bbs, *addr)?;
//                 cfg.add_edge(current_bb_key, target_addr, ());
//                 // avoid adding an edge if the branch is unconditional
//                 if let FlowControl::ConditionalBranch = ins.flow_control() {
//                     let next_addr = find_site_bb(bbs, addr + ins.len() as u64)?;
//                     cfg.add_edge(current_bb_key, next_addr, ());
//                 }
//             }
//             FlowControl::Return
//             | FlowControl::Exception
//             | FlowControl::XbeginXabortXend
//             | FlowControl::IndirectBranch
//             | FlowControl::Interrupt => {}
//         }
//     }
//     Ok(cfg)
// }

// pub fn build_bbs(dis: &Disassembled) -> Result<BTreeMap<u64, BasicBlock>> {
//     debug!("Analyzing function cfg");
//     // (block start address -> BasicBlock)
//     let mut bbs = BTreeMap::new();
//     // the nodes of the cfg are block start addresses
//     let original_bb = BasicBlock {
//         start: dis
//             .first_key_value()
//             .ok_or(anyhow!("No instruction found in the disassembly"))?
//             .1
//             .ip(),
//         end: *dis
//             .last_key_value()
//             .ok_or(anyhow!("No instruction found in the disassembly"))?
//             .0,
//     };

//     bbs.insert(original_bb.start, original_bb);
//     debug!("Beginning of analysis: Basic blocks: {:x?}", bbs);

//     for (addr, ins) in dis {
//         debug!(
//             "Analyzing instruction: {:?} @ 0x{:x}, {:?}, mnemonic: {:?}",
//             ins,
//             addr,
//             ins.flow_control(),
//             ins.mnemonic()
//         );
//         match ins.flow_control() {
//             // Block continues
//             FlowControl::Next | FlowControl::Call => {}
//             FlowControl::UnconditionalBranch | FlowControl::ConditionalBranch => {
//                 split(&mut bbs, *addr, ins.len() as u64)?;
//                 let target = get_branch_target(ins);
//                 let target_prev = *dis.range(..target).last().unwrap().0;
//                 split(
//                     &mut bbs,
//                     target_prev,
//                     dis.get(&target_prev).unwrap().len() as u64,
//                 )?;
//             }
//             FlowControl::IndirectCall | FlowControl::IndirectBranch => {
//                 warn!("Indirect control flow detected at {:x}", addr)
//             }
//             FlowControl::XbeginXabortXend | FlowControl::Interrupt => {
//                 error!("Unexpected control flow at {:x}, {:x?}", addr, ins);
//             }
//             // ud2 is considered exception, and usually presented after return
//             // Block ends when seeing these instructions
//             FlowControl::Return | FlowControl::Exception => {
//                 split(&mut bbs, *addr, ins.len() as u64)?;
//             }
//         }
//     }
//     Ok(bbs)
// }

// fn get_branch_target(ins: &Instruction) -> u64 {
//     let target = ins.near_branch_target();
//     if target == 0 {
//         panic!("problematic branch target: {:?}", ins);
//     }
//     target
// }

// /// Split the basic block at the given address
// /// A new block will be added from (site + site_ins_len) to previous end
// /// The key for the added basic block is returned
// fn split(bbs: &mut BTreeMap<u64, BasicBlock>, site: u64, site_ins_length: u64) -> Result<u64> {
//     let bb_key_to_split = find_site_bb(bbs, site)?;
//     match bbs.get_mut(&bb_key_to_split) {
//         Some(prev_bb) => {
//             if site == prev_bb.end {
//                 debug!("really no need to split @ 0x{:x}", site);
//                 return Ok(site);
//             }
//             debug!(
//                 "Splitting block: 0x{:x?} at 0x{:x} with length {}",
//                 bb_key_to_split, site, site_ins_length
//             );
//             let new_bb = BasicBlock {
//                 start: site + site_ins_length,
//                 end: prev_bb.end,
//             };
//             let result = new_bb.start;
//             assert!(new_bb.end >= new_bb.start);
//             prev_bb.end = site;
//             bbs.insert(new_bb.start, new_bb);
//             debug!("Splitting done, blocks: {:x?}", bbs);
//             return Ok(result);
//         }
//         None => {
//             panic!("Basic block not found at 0x{:x}", bb_key_to_split);
//         }
//     }
// }

// fn find_site_bb(bbs: &BTreeMap<u64, BasicBlock>, site_addr: u64) -> Result<u64> {
//     // target + 1 since the upper bound is exclusive
//     let results = bbs.range(..(site_addr + 1));
//     let site = results.last().ok_or(anyhow!(
//         "No split site found for target address 0x{:x}",
//         site_addr
//     ))?;
//     if (site.1.end < site_addr) || (site.1.start > site_addr) {
//         return Err(anyhow!("incorrect split site found"));
//     }
//     Ok(*site.0)
// }
