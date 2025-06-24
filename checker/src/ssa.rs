use crate::dis::{BasicBlock, ControlFlowInfo, Disassembled};
use crate::policy::Verifier;
use crate::semantics::*;
use anyhow::{anyhow, Result};
use iced_asm::{Instruction, Mnemonic, Register};
use ir::*;
use std::collections::{btree_map::Range, BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::Into;
use std::ops::Bound::Included;
use std::sync::{Arc, Mutex};

pub struct SubscriptAdder(Subscript);

impl SubscriptAdder {
    fn take_sub(&mut self) -> Subscript {
        self.0 = self.0.checked_add(1).unwrap();
        self.0
    }

    fn check_sub(&self) -> Subscript {
        self.0
    }

    fn new() -> Self {
        Self(0)
    }
}

#[derive(Debug)]
pub struct PhiInfo {
    pub current_sub: Subscript,
    // basic blok address -> subscript from the block
    pub incoming_map: HashMap<u64, Subscript>,
    pub new_sub: bool,
}

impl PhiInfo {
    fn add_incoming(
        &mut self,
        sub: Subscript,
        addr: u64,
        sub_adder: &Arc<Mutex<SubscriptAdder>>,
    ) -> Subscript {
        match self.incoming_map.get_mut(&addr) {
            // pre-existed subscript, return directly since nothing changed
            Some(s) if *s == sub => {
                return self.current_sub;
            }
            // new subscript, need to update current subscript and the map
            Some(s) => {
                *s = sub;
            }
            None => {
                self.incoming_map.insert(addr, sub);
            }
        }
        // Really create a new subscript if needed
        if self.incoming_map.len() >= 2 && self.new_sub == false {
            let unique_subs = self
                .incoming_map
                .iter()
                .map(|(_, sub)| *sub)
                .collect::<HashSet<_>>();
            // If all incoming edges have the same subscript, no need to create a new one
            if unique_subs.len() > 1 {
                // When we need a real phi node, create a new subscript
                self.current_sub = sub_adder.lock().unwrap().take_sub();
                self.new_sub = true;
            }
        }

        // Keep the old when when there is more than two incoming edge, as its already allocated
        self.current_sub
    }

    fn new_from(sub: Subscript, addr: u64) -> Self {
        let mut incoming_map = HashMap::new();
        incoming_map.insert(addr, sub);
        Self {
            current_sub: sub,
            incoming_map,
            new_sub: false,
        }
    }

    pub fn current_loc(&self) -> Box<dyn Fn(SSALocation) -> LocationSub + '_> {
        Box::new(|loc| Sub {
            loc,
            sub: self.current_sub,
        })
    }

    pub fn incoming_locs(&self) -> Box<dyn Fn(SSALocation) -> HashSet<LocationSub> + '_> {
        Box::new(|loc| {
            self.incoming_map
                .iter()
                .map(|(_, sub)| Sub { loc, sub: *sub })
                .collect()
        })
    }
}

pub type PhiMap = HashMap<SSALocation, PhiInfo>;

#[derive(Debug)]
pub struct BBInterpretation {
    pub predecessors: HashSet<u64>,
    // input/initial state of the basic block
    pub in_ssa: SSAState,
    // new subscript -> (old subscript, coming bb index)
    pub loc_phis: PhiMap,
    pub stack_phis: HashMap<i64, PhiInfo>,
    pub visited: bool,
}

impl BBInterpretation {
    fn empty() -> Self {
        Self {
            predecessors: HashSet::new(),
            in_ssa: SSAState::new(),
            loc_phis: HashMap::new(),
            stack_phis: HashMap::new(),
            visited: false,
        }
    }

    /// Merge from another SSA, add phis, and return if it has been changed
    fn merge(
        &mut self,
        incoming_ssa: &SSAState,
        incoming_addr: u64,
        sub_adder: &Arc<Mutex<SubscriptAdder>>,
        ssa_map: &mut SSAMap,
        bb: &BasicBlock,
    ) -> bool {
        if self.in_ssa == *incoming_ssa {
            // reach fixpoint
            return false;
        }
        // Stack offset check
        if self.in_ssa.stack_offset != incoming_ssa.stack_offset {
            panic!("Stack offset is assumed equal for all incoming edges");
        }
        // Handling Regs/Flags/Mem
        let old_state = self.in_ssa.clone();
        let self_locs: HashSet<SSALocation> = self
            .in_ssa
            .map
            .keys()
            .map(|k: &GenericLocation<SubRegister>| k.clone())
            .collect();
        let other_locs: HashSet<SSALocation> = incoming_ssa.map.keys().map(|k| k.clone()).collect();
        let mut result = SSAState::new();
        result.stack_offset = self.in_ssa.stack_offset;

        for l in self_locs.union(&other_locs) {
            match (self.in_ssa.map.get(l), incoming_ssa.map.get(l)) {
                (Some(_), Some(other_sub)) => {
                    let current_sub = match self.loc_phis.get_mut(l) {
                        Some(pi) => pi.add_incoming(*other_sub, incoming_addr, sub_adder),
                        None => {
                            panic!("No phi info for location {:?} in bb {:x}", l, incoming_addr);
                        }
                    };
                    result.map.insert(l.clone(), current_sub);
                }
                // if there are only registers, this path should not be taken?
                (Some(self_sub), None) => {
                    result.map.insert(l.clone(), self_sub.clone());

                }
                (None, Some(other_sub)) => {
                    let pi: PhiInfo = PhiInfo::new_from(*other_sub, incoming_addr);
                    self.loc_phis.insert(l.clone(), pi);
                    result.map.insert(l.clone(), other_sub.clone());
                }
                (None, None) => {
                    unreachable!()
                }
            }
        }
        // handling stack
        // Potential problems: mismatched stack offset/size => invalidate
        for offset in self.in_ssa.union_stack_offsets(&incoming_ssa) {
            match (
                self.in_ssa.stack.get(&offset),
                incoming_ssa.stack.get(&offset),
            ) {
                (Some((self_size, _)), Some((_other_size, other_sub))) => {
                    // if self_size != other_size {
                    //     // maybe we should havoc this stack cell
                    //     panic!("Mismatched stack size at offset {:x}", offset);
                    // }
                    let current_sub = match self.stack_phis.get_mut(&offset) {
                        Some(pi) => pi.add_incoming(*other_sub, incoming_addr, sub_adder),
                        None => {
                            panic!(
                                "No phi info at stack offset {:?} in bb {:x}",
                                offset, incoming_addr
                            );
                        }
                    };
                    result.stack.insert(offset, (*self_size, current_sub));
                }
                // if there are only registers, this path should not be taken?
                (Some(self_pair), None) => {
                    result.stack.insert(offset, *self_pair);
                }
                (None, Some((other_size, other_sub))) => {
                    let pi: PhiInfo = PhiInfo::new_from(*other_sub, incoming_addr);
                    self.stack_phis.insert(offset, pi);
                    result.stack.insert(offset, (*other_size, *other_sub));
                }
                (None, None) => {
                    unreachable!()
                }
            }
        }

        result.validate_stack().unwrap();

        // must be true here?
        self.in_ssa = result;
        // trace!("Merged state {:?}", self.in_ssa);
        // trace!("Merged phis {:?}", self.loc_phis);
        // trace!("Merged stack phis {:?}", self.stack_phis);
        // update all the occurrence of the old subscript to the new one
        for (_, ins_ssa) in ssa_map.range_mut((Included(&bb.start), Included(&bb.end))) {
            ins_ssa.bb_update(&old_state, &self.in_ssa)
        }

        self.in_ssa != old_state
    }

    // fn update_in_ssa(&mut self, in_ssa: &SSAState) {
    //     self.in_ssa = in_ssa.clone();
    // }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SSAState {
    pub map: HashMap<SSALocation, Subscript>,
    pub stack_offset: i64,
    // stack maps from the offset to the size of the cell and its subscript
    pub stack: BTreeMap<i64, (ValSize, Subscript)>,
    pub aliases: Vec<(LocationSub, Alias)>, // stack here?
}

impl SSAState {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            stack_offset: 0,
            stack: BTreeMap::new(),
            aliases: Vec::new(),
        }
    }

    fn init_regs(&mut self, sub_adder: &Arc<Mutex<SubscriptAdder>>) {
        let mut adder = sub_adder.lock().unwrap();
        // assert that this function can only be invoked once
        assert_eq!(adder.check_sub(), 0);
        for r in Register::values().filter(|r| Register::is_gpr64(*r) || Register::is_xmm(*r)) {
            let ssr = self.convert_to_ss(&Location::Register(r));
            self.map.insert(ssr, adder.take_sub());
        }
        let lb = self.convert_to_ss(&Location::MAS(MicroArchitecturalState::LoadBuffer));
        self.map.insert(lb, adder.take_sub());
    }

    pub fn get_loc_ssa(&self, loc: &SSALocation) -> Option<LocationSub> {
        match self.map.get(loc) {
            Some(sub) => Some(Sub {
                loc: loc.clone(),
                sub: *sub,
            }),
            None => None,
        }
    }

    pub fn get_loc_sub(&self, loc: &SSALocation) -> Option<Subscript> {
        match self.map.get(loc) {
            Some(sub) => Some(*sub),
            None => None,
        }
    }

    pub fn convert_to_ss(&self, loc: &Location) -> SSALocation {
        match loc {
            Location::Flag(f) => SSALocation::Flag(*f),
            Location::MAS(mas) => SSALocation::MAS(*mas),
            Location::Register(r) => SSALocation::Register(*r),
            // Reading from memory may return ANY instead
            Location::Memory(m) => {
                let m_ssa = GenericMemCell {
                    base_reg: SubRegister::from(
                        m.base_reg,
                        *self
                            .map
                            .get(&SSALocation::Register(m.base_reg))
                            .unwrap_or(&0),
                    ),
                    index_reg: SubRegister::from(
                        m.index_reg,
                        *self
                            .map
                            .get(&SSALocation::Register(m.index_reg))
                            .unwrap_or(&0),
                    ),
                    index_scale_negtive: m.index_scale_negtive,
                    displacement: m.displacement,
                    scale: m.scale,
                    size: m.size,
                };
                SSALocation::Memory(m_ssa)
            }
            Location::Stack(_) => panic!("Stack locations are not supported in SSA"),
        }
    }

    pub fn handle_assignment(
        &mut self,
        a: &Assignment,
        _ins: &Instruction,
        adder: &mut Arc<Mutex<SubscriptAdder>>,
    ) -> SSAsgn {
        let rhs_ssa = convert_expr(self, &a.rhs, adder);
        let ss_lhs = self.convert_to_ss(&a.lhs);
        let ss_lhs_sub = adder.lock().unwrap().take_sub();
        self.map.insert(ss_lhs.clone(), ss_lhs_sub.clone());
        // info!("Assign {:?} in proof, sub++", a.left_hand_side);
        SSAsgn {
            lhs: Sub::from(ss_lhs, ss_lhs_sub),
            rhs: rhs_ssa,
        }
    }

    pub fn get_stack_offset(&self, m: &GenericMemCell<Sub<Register>>) -> Result<i64> {
        // Sanity checks
        if !m.is_rsp_ralted() {
            return Err(anyhow!("Stack memory cell is should be rsp-related"));
        }
        if m.index_reg.loc != Register::None {
            return Err(anyhow!("Stack memory cell should not have index reg"));
        }
        let offset = self.stack_offset - (m.displacement as i64);
        if offset < 0 {
            return Err(anyhow!("Stack memory offset should be positive"));
        }
        Ok(offset)
    }

    fn handle_stack_related(
        &mut self,
        a: &SSAsgn,
        adder: &mut Arc<Mutex<SubscriptAdder>>,
    ) -> Result<()> {
        match a.lhs.get_loc() {
            GenericLocation::Register(r) if *r == Register::RSP => {
                match &a.rhs {
                    // End of function
                    // TODO: check stack balanced!
                    SSExpr::Var(v)
                        if let GenericLocation::Register(r) = v.get_loc()
                            && *r == Register::RBP =>
                    {
                        Ok(())
                    }
                    SSExpr::Binary(BinaryOp::BV(BVBinaryOp::Arith(bvaop)), e1, e2) => {
                        match (e1.as_ref(), e2.as_ref()) {
                            (
                                SSExpr::Var(Sub {
                                    loc: GenericLocation::Register(Register::RSP),
                                    sub: _,
                                }),
                                SSExpr::Imm(i),
                            )
                            | (
                                SSExpr::Imm(i),
                                SSExpr::Var(Sub {
                                    loc: GenericLocation::Register(Register::RSP),
                                    sub: _,
                                }),
                            ) => {
                                match bvaop {
                                    // Stack grows down (towards lower addresses)
                                    BVBinaryArith::Add => {
                                        self.stack_offset -= i.value();
                                    }
                                    BVBinaryArith::Sub => {
                                        self.stack_offset += i.value();
                                    }
                                    _ => {
                                        Err(anyhow!("Unexpected stack pointer assignment {:?}", a))?
                                    }
                                }
                                if self.stack_offset < 0 {
                                    Err(anyhow!("Stack offset is negative"))
                                } else {
                                    Ok(())
                                }
                            }
                            _ => Err(anyhow!("Unexpected stack pointer assignment {:?}", a)),
                        }
                    }
                    _ => Err(anyhow!("Unexpected stack pointer assignment {:?}", a)),
                }
            }
            GenericLocation::Memory(m) if m.is_rsp_ralted() => {
                let offset = self.get_stack_offset(&m)?;
                let sub: usize = adder.lock().unwrap().take_sub();
                self.stack.insert(offset, (m.size, sub));
                // TODO: update the subscripts when merge branches
                let stack_alias = Alias::new(AliasInner::Stack(offset), m.size, Some(sub));
                self.aliases.push((a.lhs.clone(), stack_alias));
                Ok(())
            }
            // not a stack-related operation
            _ => Ok(()),
        }?;

        let rhs_stack_uses = a.rhs.stack_uses();
        rhs_stack_uses.iter().for_each(|m| {
            let mem: GenericMemCell<Register> = m.get_loc().try_take_memcell().unwrap().into();
            // pay attention to this!
            let offset = self.stack_offset - (mem.displacement as i64);
            let (size, sub) = self.stack.get(&offset).unwrap();
            self.aliases.push((
                m.clone(),
                Alias::new(AliasInner::Stack(offset), *size, Some(*sub)),
            ));
        });
        Ok(())
    }

    // Return the union of stack offsets
    pub fn union_stack_offsets(&self, other: &Self) -> HashSet<i64> {
        let mut offsets = HashSet::new();
        self.stack.keys().for_each(|k| {
            offsets.insert(*k);
        });
        other.stack.keys().for_each(|k| {
            offsets.insert(*k);
        });
        offsets
    }

    pub fn validate_stack(&self) -> Result<()> {
        let mut last_position = 0;
        for (offset, (size, _)) in self.stack.iter() {
            if *offset < last_position {
                return Err(anyhow!("Stack doesn't grow validly"));
            }
            last_position = offset + (size.size_bytes() as i64);
        }

        Ok(())
    }
}

// #[derive(Debug, Clone, PartialEq)]
// pub struct Stack {
//     pub stack_growth: u64,
//     // stack stores the SSA-formed stack variables
//     pub stack: BTreeMap<u64, (SSALocation, Subscript)>,
// }

// impl Stack {
//     pub fn init() -> Self {
//         Self {
//             stack_growth: 0,
//             stack: BTreeMap::new(),
//         }
//     }

//     pub fn next_frame(
//         &self,
//         air: Vec<Assignment>,
//         global_sub: &mut Arc<Mutex<SubscriptAdder>>,
//     ) -> Self{
//         unimplemented!()
//     }
// }

// All state here is the state after the instruction is executed
#[derive(Debug, Clone, PartialEq)]
pub struct InsSSA {
    // These three states are SSA specific
    pub ssa: SSAState,
    pub ss_asgns: SSAAssignments,
    pub ss_rels: SSARelationships,
    pub written_locations: HashSet<SSALocation>,
    pub read_locations: HashSet<SSALocation>,
}

impl InsSSA {
    pub fn bb_update(&mut self, old_ssa: &SSAState, new_ssa: &SSAState) {
        for (loc, sub) in self.ssa.map.iter_mut() {
            match old_ssa.get_loc_sub(loc) {
                // update the subscript if its been changed to the new one
                Some(old_sub) if *sub == old_sub => {
                    *sub = new_ssa.get_loc_sub(loc).unwrap();
                }
                _ => {}
            }
        }

        for a in self.ss_asgns.iter_mut() {
            subst_subscript_with_ssa(old_ssa, new_ssa, a);
        }
    }
}

impl PartialOrd for InsSSA {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // all keys in self are also in other
        let (greater, less, self_greater) =
            if self.ssa.map.keys().all(|k| other.ssa.map.contains_key(k)) {
                (&other.ssa, &self.ssa, false)
            } else if other.ssa.map.keys().all(|k| self.ssa.map.contains_key(k)) {
                (&self.ssa, &other.ssa, true)
            } else {
                return None;
            };

        for (loc, sub) in &less.map {
            // Greater must contain the same key, and the subscript must be greater for all locations
            if greater.map[loc] < *sub {
                return None;
            }
        }

        if self_greater {
            Some(std::cmp::Ordering::Greater)
        } else {
            Some(std::cmp::Ordering::Less)
        }
    }
}

/// SSAMap store the state *after* interpreting the proof
pub type SSAMap = BTreeMap<u64, InsSSA>;
/// BB First inst
pub type BBSSAMap = HashMap<u64, BBInterpretation>;

#[derive(Debug)]
pub struct FuncSSA {
    pub init_ssa: SSAState, // TODO: This should be an immutable reference? Access through API maybe?
    pub ssa_map: SSAMap,
    pub bb_map: BBSSAMap,
}

#[cfg(feature = "wasmsfi")]
impl FuncSSA {
    pub fn get_heapbase(&self) -> Option<LocationSub> {
        self.init_ssa.get_loc_ssa(&Register::RDI.into())
    }

    pub fn get_stackbase(&self) -> Option<LocationSub> {
        self.init_ssa.get_loc_ssa(&Register::RSP.into())
    }
}

pub fn ssa(
    cfi: &ControlFlowInfo,
    dis: &Disassembled,
    semantics_map: &HashMap<u64, Semantics>,
    verifier: &Verifier,
) -> Result<FuncSSA> {
    let mut global_sub: Arc<Mutex<SubscriptAdder>> = Arc::new(Mutex::new(SubscriptAdder::new()));
    let mut ssa_map: SSAMap = BTreeMap::new();
    let mut bb_ai_map = BBSSAMap::new();
    let first_ins_addr = cfi.first_ins_addr();
    for (bb_addr, _) in &cfi.basic_blocks {
        bb_ai_map.insert(*bb_addr, BBInterpretation::empty());
    }
    let mut first_bb_ai = BBInterpretation::empty();
    first_bb_ai.in_ssa.init_regs(&global_sub);
    let init_ssa = first_bb_ai.in_ssa.clone();
    let mut init_regs_assignments: Vec<GenericAssignment<LocationSub, LocationSub>> = Vec::new();
    for (loc, sub) in &first_bb_ai.in_ssa.map {
        let lhs = Sub::from(loc.clone(), sub.clone());
        init_regs_assignments.push(GenericAssignment {
            rhs: SSExpr::Any(lhs.get_sort().into()),
            lhs,
        });
    }
    bb_ai_map.insert(first_ins_addr, first_bb_ai);
    let mut worklist: VecDeque<u64> = VecDeque::new();
    worklist.push_back(first_ins_addr);
    // skeleton from VeriWASM
    while !worklist.is_empty() {
        let addr = worklist.pop_front().unwrap();
        let bb_info = cfi.basic_blocks.get(&addr).unwrap();
        let bb_ins = dis.range((Included(&bb_info.start), Included(&bb_info.end)));
        let bb_interp = bb_ai_map.get_mut(&addr).unwrap();
        // end state after processing the basic block (at the control flow related instruction)
        let branch_state = interpret_bb(
            bb_info.start,
            bb_interp,
            &mut ssa_map,
            bb_ins,
            semantics_map,
            &mut global_sub,
            verifier,
        )?;
        let succ_addrs: Vec<u64> = cfi.control_flow_graph.neighbors(addr).collect();
        log::debug!("Processing Block: 0x{:x} -> {:x?}", addr, succ_addrs);
        for succ_addr in succ_addrs {
            // visited by interpret_bb
            // Add enough pre-merging information
            let succ_bb = bb_ai_map.get_mut(&succ_addr).unwrap();
            succ_bb.predecessors.insert(addr);
            succ_bb.in_ssa.stack_offset = branch_state.stack_offset;
            let succ_bb_interp = bb_ai_map.get_mut(&succ_addr).unwrap();
            // TODO optimize
            let has_change = if ssa_map.contains_key(&succ_addr) {
                // NOTE: merge all states in the bb
                succ_bb_interp.merge(
                    &branch_state,
                    addr,
                    &global_sub.clone(),
                    &mut ssa_map,
                    cfi.basic_blocks.get(&succ_addr).unwrap(),
                )
            } else {
                // debug!("At block 0x{:x}: new input {:?}", succ_addr, branch_state);
                succ_bb_interp.merge(
                    &branch_state,
                    addr,
                    &global_sub.clone(),
                    &mut ssa_map,
                    cfi.basic_blocks.get(&succ_addr).unwrap(),
                );
                true
            };

            if has_change && !worklist.contains(&succ_addr) {
                worklist.push_back(succ_addr);
            }
        }

        // debug!("Worklist: {:x?}", worklist);
    }

    let first_ai = ssa_map.get_mut(&first_ins_addr).unwrap();
    first_ai.ss_asgns.append(init_regs_assignments.as_mut());

    Ok(FuncSSA {
        init_ssa,
        ssa_map,
        bb_map: bb_ai_map,
    })
}

/// interpret a basic block until its end
/// return the ending state
fn interpret_bb<'a>(
    _start_addr: u64,
    bb_interp: &mut BBInterpretation,
    ssa_map: &mut SSAMap,
    dis: Range<'a, u64, Instruction>,
    semantics_map: &HashMap<u64, Semantics>,
    subscript: &mut Arc<Mutex<SubscriptAdder>>,
    verifier: &Verifier,
) -> Result<SSAState> {
    // assuming that the (uninterpreted) initial state is already in the statemap
    let mut last_ssa = bb_interp.in_ssa.clone();
    let visited = bb_interp.visited;
    // Sanity Check: This may not be a reasonable assumption
    // println!("Interpreting BB 0x{:X}", start_addr);
    // println!("Using SSA {:?} ", last_ssa);
    // if visited {
    //     let mut phi_locs = BTreeSet::new();
    //     let mut fist_locs = BTreeSet::new();
    //     for loc in bb_interp.phis.keys() {
    //         phi_locs.insert(loc);
    //     }
    //     for loc in ssa_map.get(&start_addr).unwrap().ssa.map.keys() {
    //         fist_locs.insert(loc);
    //     }
    //     println!("difference1: {:?} ", phi_locs.difference(&fist_locs).cloned().collect::<Vec::<_>>());
    //     println!("difference2: {:?} ", fist_locs.difference(&phi_locs).cloned().collect::<Vec::<_>>());
    //     assert_eq!(phi_locs, fist_locs);
    //     println!(
    //         "Visited; old SSA {:?} ",
    //         ssa_map.get(&start_addr).unwrap().ssa
    //     );
    // }

    for (addr, ins) in dis {
        match semantics_map.get(&addr) {
            Some(sem) => {
                let mut new_ai = if visited {
                    ssa_map.get(addr).unwrap().clone()
                } else {
                    step(
                        &last_ssa,
                        ins,
                        &sem.assignments,
                        &sem.relationships,
                        subscript,
                        verifier,
                    )?
                };
                // Use different SSAs for read and write locations
                new_ai.read_locations = sem
                    .read_locations
                    .iter()
                    .map(|l| last_ssa.convert_to_ss(l))
                    .collect();
                // println!("New AI SSA: {:?}", new_ai.ssa);
                last_ssa = new_ai.ssa.clone();
                new_ai.written_locations = sem
                    .written_locations
                    .iter()
                    .map(|l| last_ssa.convert_to_ss(l))
                    .collect();
                ssa_map.insert(*addr, new_ai);
            }
            None => {
                return Err(anyhow::anyhow!("No semantics found for 0x{:x}", addr));
            }
        }
        // last_ssa = ssa_map.get(addr).unwrap().ssa;
        // debug!("Assignments: {:?}", assignments);
        // debug!("Relationships: {:?}", relationships);
    }
    bb_interp.visited = true;
    Ok(last_ssa.clone())
}

fn subst_subscript_with_ssa(old_ssa: &SSAState, new_ssa: &SSAState, asgn: &mut SSAsgn) -> () {
    fn subst_location(old_ssa: &SSAState, new_ssa: &SSAState, loc: &LocationSub) -> LocationSub {
        let location = loc.loc.clone();
        match old_ssa.map.get(&location) {
            Some(old_sub) if *old_sub == loc.sub => Sub {
                sub: *new_ssa.map.get(&location).unwrap(),
                loc: location,
            },
            _ => loc.clone(),
        }
    }

    fn subst_expr(old_ssa: &SSAState, new_ssa: &SSAState, expr: &SSExpr) -> SSExpr {
        match expr {
            SSExpr::Var(v) => SSExpr::Var(subst_location(old_ssa, new_ssa, v)),
            SSExpr::Unary(op, e) => {
                SSExpr::Unary(op.clone(), Box::new(subst_expr(old_ssa, new_ssa, e)))
            }
            SSExpr::Binary(op, e1, e2) => SSExpr::Binary(
                op.clone(),
                Box::new(subst_expr(old_ssa, new_ssa, e1)),
                Box::new(subst_expr(old_ssa, new_ssa, e2)),
            ),
            SSExpr::Ite(econd, eethen, eelse) => SSExpr::Ite(
                Box::new(subst_expr(old_ssa, new_ssa, econd)),
                Box::new(subst_expr(old_ssa, new_ssa, eethen)),
                Box::new(subst_expr(old_ssa, new_ssa, eelse)),
            ),
            SSExpr::Any(_) | SSExpr::Imm(_) | SSExpr::Const(_) | SSExpr::Alias(_) => expr.clone(),
        }
    }

    asgn.lhs = subst_location(old_ssa, new_ssa, &asgn.lhs);
    asgn.rhs = subst_expr(old_ssa, new_ssa, &asgn.rhs);
}

/// step on the input SSAState and return an InsAI (interpret assignments normally)
fn step(
    in_ssa: &SSAState,
    ins: &Instruction,
    air: &Vec<Assignment>,
    rels: &Vec<Relationship>,
    global_sub: &mut Arc<Mutex<SubscriptAdder>>,
    verifier: &Verifier,
) -> Result<InsSSA> {
    let mut new_ssa = in_ssa.clone();
    let mut assignments: SSAAssignments = Vec::new();
    // TODO: enforce the sequence of proofs
    // Deal with assignments first
    for a in air {
        // if let Location::Flag(_) = a.left_hand_side {
        //     continue
        // }
        // let mut global_sub = global_sub.lock().unwrap();
        let ssa_asgn = new_ssa.handle_assignment(a, ins, global_sub);
        // Avoid `ret` instructions for now as it minus the stack offset to a negative number
        if ins.mnemonic() != Mnemonic::Ret && verifier.binary_type.is_wasm() {
            new_ssa.handle_stack_related(&ssa_asgn, global_sub)?;
            new_ssa.validate_stack()?;
        }
        assignments.push(ssa_asgn);

        // let rhs_ssa = convert_expr(&mut new_ssa, &a.right_hand_side, global_sub);
        // let ss_lhs = new_ssa.convert_to_ss(&a.left_hand_side);
        // let ss_lhs_sub = global_sub.lock().unwrap().take_sub();
        // new_ssa.map.insert(ss_lhs.clone(), ss_lhs_sub.clone());
        // // let new_lhs = LocationAI::Plain(state.get_loc(&a.left_hand_side).clone());
        // assignments.push(SSAsgn {
        //     left_hand_side: LocationSub {
        //         location: ss_lhs,
        //         sub: ss_lhs_sub,
        //     },
        //     right_hand_side: rhs_ssa,
        // });
    }

    let mut relationships: SSARelationships = Vec::new();
    for r in rels {
        let lhs_ssa = convert_expr(&mut new_ssa, &r.lhs, global_sub);
        let rhs_ssa = convert_expr(&mut new_ssa, &r.rhs, global_sub);
        relationships.push(rel!(lhs_ssa, r.relationship, rhs_ssa));
    }

    // Deal with relationships next, on the new state with assignments coped first
    // for p in proofs {
    //     if let Proof::Rel(r) = p {
    //         // let mut state = state.lock().unwrap();
    //         // should relationships use new_ssa or in_ssa?
    //         let lhs_ssa = convert_expr(&new_ssa, &r.left_hand_side);
    //         let rhs_ssa = convert_expr(&new_ssa, &r.right_hand_side);
    //         state.lock().unwrap().relationships.push(SSRel {
    //             relationship: r.relationship.clone(),
    //             left_hand_side: lhs_ssa,
    //             right_hand_side: rhs_ssa,
    //         })
    //     }
    // }
    // TODO: handle annotations
    Ok(InsSSA {
        ss_asgns: assignments,
        ss_rels: relationships,
        ssa: new_ssa,
        read_locations: HashSet::new(),
        written_locations: HashSet::new(),
    })
}

// fn _convert_rel(
//     ssa: &mut SSAState,
//     rel: &Relationship,
//     global_sub: &mut Arc<Mutex<SubscriptAdder>>,
// ) -> SSRel {
//     SSRel {
//         relationship: rel.relationship.clone(),
//         lhs: convert_expr(ssa, &rel.lhs, global_sub),
//         rhs: convert_expr(ssa, &rel.rhs, global_sub),
//     }
// }

// Use abstract interpreted values to represent the expression
fn convert_expr(
    ssa: &mut SSAState,
    expr: &Expr,
    global_sub: &mut Arc<Mutex<SubscriptAdder>>,
) -> SSExpr {
    // info!("Converting expr: {:?}, ssa: {:?}", expr, ssa);
    match expr {
        // Need special handling for partial registers!
        Expr::Var(v) => match ssa.get_loc_ssa(&ssa.convert_to_ss(v)) {
            Some(v) => GenericExpr::Var(v),
            None => {
                assert!(v.is_memory()); // only memory may not be found in SSAState
                let sub = global_sub.lock().unwrap().take_sub();
                ssa.map.insert(ssa.convert_to_ss(v), sub);
                let mem_loc_ss = Sub {
                    loc: ssa.convert_to_ss(v),
                    sub,
                };
                GenericExpr::Var(mem_loc_ss)
            }
        },
        Expr::Imm(c) => GenericExpr::Imm(*c),
        Expr::Binary(op, lhs, rhs) => GenericExpr::Binary(
            *op,
            Box::new(convert_expr(ssa, lhs, global_sub)),
            Box::new(convert_expr(ssa, rhs, global_sub)),
        ),
        Expr::Unary(op, e) => {
            GenericExpr::Unary(op.clone(), Box::new(convert_expr(ssa, e, global_sub)))
        }
        Expr::Any(s) => GenericExpr::Any(s.clone()),
        Expr::Alias(a) => GenericExpr::Alias(a.clone()),
        Expr::Const(c) => GenericExpr::Const(c.clone()),
        Expr::Ite(cond, ethen, eelse) => GenericExpr::Ite(
            Box::new(convert_expr(ssa, cond, global_sub)),
            Box::new(convert_expr(ssa, ethen, global_sub)),
            Box::new(convert_expr(ssa, eelse, global_sub)),
        ),
    }
}

#[cfg(test)]
mod ssa_testing {
    use super::*;

    #[test]
    fn test_adder() {
        let global_sub: Arc<Mutex<SubscriptAdder>> = Arc::new(Mutex::new(SubscriptAdder::new()));
        let adder_clone1 = global_sub.clone();
        let adder_clone2 = global_sub.clone();
        {
            assert_eq!(adder_clone1.lock().unwrap().take_sub(), 1);
        }
        {
            assert_eq!(adder_clone2.lock().unwrap().take_sub(), 2);
        }
    }
}
