use anyhow::{anyhow, Result};
use iced_asm::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
    RflagsBits,
};
use ir::*;
use lazy_static::lazy_static;
use log::{debug, trace, warn};
use std::collections::{HashMap, HashSet};

// to handle partial registers
pub type Continuation = Box<dyn Fn(Expr) -> Expr>;

// These instructions don't need to be fenced after
lazy_static! {
    pub static ref AVOID_FENCE_AFTER: HashSet<Mnemonic> = {
        let mut set = HashSet::new();
        set.insert(Mnemonic::Ret);
        set.insert(Mnemonic::Call);
        set.insert(Mnemonic::Pop);
        set.insert(Mnemonic::Lfence);
        set.insert(Mnemonic::Leave);
        set
    };
    pub static ref CALLER_SAVED_REGS: HashSet<Register> = {
        let mut set = HashSet::new();
        set.insert(Register::RAX);
        set.insert(Register::RCX);
        set.insert(Register::RDX);
        set.insert(Register::R8);
        set.insert(Register::R9);
        set.insert(Register::R10);
        set.insert(Register::R11);
        set
    };
}

#[derive(Debug, Clone)]
pub struct Semantics {
    // [complete] assignment semantics
    pub assignments: Vec<Assignment>,
    pub relationships: Vec<Relationship>,
    // These are for policy: WASM SFI
    pub written_locations: HashSet<Location>,
    pub read_locations: HashSet<Location>,
}

#[macro_export]
macro_rules! flags_matching {
    ($target_vec: ident, $target_flagu32: ident, $($flagname: ident, )+) => {
        $(if $target_flagu32 & RflagsBits::$flagname != 0 {
            $target_vec.insert(Location::Flag(Flags::$flagname));
        }) +
    }
}

pub fn lift<'a, T>(disassembled: T) -> Result<HashMap<u64, Semantics>>
where
    T: Iterator<Item = (&'a u64, &'a Instruction)>,
{
    let mut semantics_map = HashMap::new();
    for (addr, ins) in disassembled {
        debug!("lifting instruction at addr: 0x{:x}", addr);
        semantics_map.insert(*addr, lift_ins(ins)?);
    }
    Ok(semantics_map)
}

fn lift_ins(ins: &Instruction) -> Result<Semantics> {
    trace!("Lifting instruction: {:x?}", ins);
    let mut rel_semantics = vec![];
    // Architectural level semantics
    let mut asgn_semantics = match ins.mnemonic() {
        Mnemonic::Push => push(ins)?,
        Mnemonic::Mov
        | Mnemonic::Movq
        | Mnemonic::Movaps
        | Mnemonic::Movd
        | Mnemonic::Movsd
        | Mnemonic::Movss
        | Mnemonic::Movsxd => mov(ins)?,
        #[cfg(feature = "wasmsfi")]
        Mnemonic::Cmovae => cmovae_lucet(ins)?,
        Mnemonic::Add => add(ins)?,
        Mnemonic::Pop => pop(ins)?,
        Mnemonic::Xor | Mnemonic::Xorpd | Mnemonic::Xorps => xor(ins)?,
        Mnemonic::Sub => sub(ins)?,
        Mnemonic::Shl => shl(ins)?,
        Mnemonic::Lea => lea(ins)?,
        Mnemonic::Call => call(ins)?,
        Mnemonic::Ret => ret(ins)?,
        // not all jcc are covered here, but seemingly enough for the setting
        Mnemonic::Jae
        | Mnemonic::Ja
        | Mnemonic::Jb
        | Mnemonic::Jbe
        | Mnemonic::Je
        | Mnemonic::Jne => jcc(ins)?,
        Mnemonic::Cmp => cmp(ins)?,
        _ => vec![],
    };

    // Microarchitectural level semantics
    let mut info_factory = InstructionInfoFactory::new();
    let info = info_factory.info(&ins);
    if ins.mnemonic() == Mnemonic::Lfence {
        asgn_semantics.push(Assignment::new(
            Location::MAS(MicroArchitecturalState::LoadBuffer),
            Imm::new(0, ValSize::Size1).into(),
        ))
    } else if !AVOID_FENCE_AFTER.contains(&ins.mnemonic())
        && info.used_memory().iter().any(|mem| {
            // println!("mem access: {:?} @ 0x{:x}", mem.access(), addr);
            match mem.access() {
                // check if it's a memory load instruction
                OpAccess::Read
                | OpAccess::CondRead
                | OpAccess::ReadCondWrite
                | OpAccess::ReadWrite => true,
                _ => false,
            }
        })
    {
        asgn_semantics.push(Assignment::new(
            Location::MAS(MicroArchitecturalState::LoadBuffer),
            Imm::new(1, ValSize::Size1).into(),
        ))
    }

    havoc_semantics(ins, &mut asgn_semantics);
    // #[cfg(not(feature = "naive_memory"))]
    // havoc_memory_writes(&mut ins_semantics);
    trace!("havoced semantics: {:?}", asgn_semantics);
    let mut asng_semantics = vec![];
    for a in asgn_semantics {
        trace!("teasing semantics: {:?}", &a);
        asng_semantics.push(tease_assignment(a)?);
    }
    trace!("teased: {:?}", asng_semantics);

    if let Ok(GenericLocation::Register(r)) = location_operand(ins, 0) && r.size() <=4 && r != Register::None {
        rel_semantics.push(rel!(Location::Register(unalias_register(r)?).into(), bv!("bvult"), Imm::from(0x100000000 as u64).into()));
    }

    debug!("lifted relationships: {:x?}", rel_semantics);
    Ok(Semantics {
        assignments: asng_semantics,
        relationships: rel_semantics,
        written_locations: get_write_destinations(ins),
        read_locations: get_read_sources(ins),
    })
}

pub fn havoc_semantics(ins: &Instruction, assgnments: &mut Vec<Assignment>) {
    // We expect that RIP is already assigned in calls and jumps

    let mut assigned_locs: HashSet<Location> = assgnments
        .iter()
        .map(|a| unalias_location(a.lhs.clone()).unwrap())
        .collect();

    // Deal with RIP change if possible
    if !assigned_locs.contains(&Location::Register(Register::RIP)) {
        if let FlowControl::Next = ins.flow_control() {
            assgnments.push(Assignment::new(
                Register::RIP.into(),
                Imm::from(ins.next_ip()).into(),
            ));
            assigned_locs.insert(Location::Register(Register::RIP));
        }
        // other cases?
    }
    // debug!("Assigned locations: {:x?}", assigned_locs);
    let mut written_locs = get_write_destinations(ins);
    match ins.flow_control() {
        FlowControl::IndirectCall | FlowControl::Call => {
            // TODO this list can be longer for better conservativeness
            CALLER_SAVED_REGS.iter().for_each(|r| {
                written_locs.insert(Location::Register(*r).into());
            });
        }
        _ => (),
    }
    // debug!("Written locations: {:x?}", written_locs);
    let havocing_locs = written_locs.difference(&assigned_locs);
    // debug!("Havocing locations: {:x?}", havocing_locs);
    for l in havocing_locs {
        assgnments.push(Assignment::new(l.clone(), Expr::Any(l.get_sort().into())));
    }
}

#[allow(dead_code)]
fn havoc_memory_writes(assgnments: &mut Vec<Assignment>) {
    for a in assgnments {
        if let Location::Memory(_) = a.lhs {
            a.rhs = Expr::Any(a.lhs.get_sort().into());
        }
    }
}

// Optimization: use HashSet instead?
fn get_read_sources(ins: &Instruction) -> HashSet<Location> {
    #[cfg(feature = "wasmsfi")]
    let skip_list: HashSet<Mnemonic> = HashSet::from_iter([Mnemonic::Ret]);
    if skip_list.contains(&ins.mnemonic()) {
        // Hardcode a short circuit for calls to hide rsp and stack changes
        let mut s = HashSet::new();
        s.insert(Location::Register(Register::RIP));
        return s;
    }
    debug!("Getting read sources for instruction: {:x?}", ins);
    let mut read_locs = HashSet::new();
    let mut info_fact = InstructionInfoFactory::new();
    let info = info_fact.info(ins);
    // registers
    for reg in info.used_registers() {
        match reg.access() {
            OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                read_locs.insert(reg.register().into());
            }
            _ => {}
        }
    }
    // Assuming RIP is always written
    read_locs.insert(Register::RIP.into());

    // flags
    let modified_flags = ins.rflags_modified();
    flags_matching!(read_locs, modified_flags, CF, PF, AF, ZF, SF, IF, DF, OF,);

    // memory
    for mem in info.used_memory() {
        match mem.access() {
            OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                trace!("Read from this memory: {:x?}", mem);
                read_locs.insert(
                    LocationBuilder::new()
                        .memcell(MemCell::try_from(mem.to_owned()).unwrap())
                        .build(),
                );
            }
            _ => {}
        }
    }

    read_locs
}

// Optimization: use HashSet instead?
fn get_write_destinations(ins: &Instruction) -> HashSet<Location> {
    // Call: we assume that calls doesn't change the state of a program, except RIP
    // Cmovae: skip the semantics for this instruction to be compatible with Lucet and Veriwasm
    // TODO: check that the rsp before `ret` is equal to the value of the initial rsp
    #[cfg(feature = "wasmsfi")]
    let skip_list: HashSet<Mnemonic> = HashSet::from_iter([Mnemonic::Call, Mnemonic::Cmovae]);
    if skip_list.contains(&ins.mnemonic()) {
        // Hardcode a short circuit for calls to hide rsp and stack changes
        let mut s = HashSet::new();
        s.insert(Location::Register(Register::RIP));
        return s;
    }
    debug!("Getting write destinations for instruction: {:x?}", ins);
    let mut write_locs = HashSet::new();
    let mut info_fact = InstructionInfoFactory::new();
    let info = info_fact.info(ins);
    // registers
    for reg in info.used_registers() {
        match reg.access() {
            OpAccess::Write
            | OpAccess::CondWrite
            | OpAccess::ReadWrite
            | OpAccess::ReadCondWrite => {
                write_locs.insert(unalias_location(Location::Register(reg.register())).unwrap());
            }
            _ => {}
        }
    }
    // Assuming RIP is always written
    write_locs.insert(Location::Register(Register::RIP));

    // flags
    let modified_flags = ins.rflags_modified();
    flags_matching!(write_locs, modified_flags, CF, PF, AF, ZF, SF, IF, DF, OF,);

    // memory
    for mem in info.used_memory() {
        match mem.access() {
            OpAccess::Write
            | OpAccess::CondWrite
            | OpAccess::ReadWrite
            | OpAccess::ReadCondWrite => {
                trace!("Written to this memory: {:?}", mem);
                write_locs.insert(
                    LocationBuilder::new()
                        .memcell(MemCell::try_from(mem.to_owned()).unwrap())
                        .build(),
                );
            }
            _ => {}
        }
    }

    write_locs
}

pub fn wild(ins: &Instruction) -> Result<Vec<Assignment>> {
    // TODO: generate havoc(s) for instructions without proof
    let mut info_fact = InstructionInfoFactory::new();
    let info = info_fact.info(ins);
    let mut semantics = Vec::new();
    warn!(
        "Instruction {:?} is currently not supported completely",
        ins
    );
    let mut read_regs = vec![];
    let mut write_regs = vec![];
    for reg in info.used_registers() {
        // havoc all registers which might be written
        // debug!("reg: {:?}", reg);
        match reg.access() {
            OpAccess::Write | OpAccess::CondWrite => {
                write_regs.push(reg.register());
            }
            OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                read_regs.push(reg.register());
                write_regs.push(reg.register());
            }
            OpAccess::Read | OpAccess::CondRead => {
                read_regs.push(reg.register());
            }
            _ => {}
        }
    }

    if ins.op_count() >= 1 {
        // assuming the first operand is the destination
        match ins.op_kind(0) {
            OpKind::Register => {
                let reg = ins.op_register(0);
                let written_full_reg_set: Vec<Register> = write_regs
                    .iter()
                    .map(|r| r.full_register())
                    .filter(|r| r.eq(&reg.full_register()))
                    .collect();

                debug!(
                    "written_reg_set: {:?}, reg: {:?}, regsize: {}",
                    written_full_reg_set,
                    reg,
                    reg.size()
                );
                // maybe just check if its empty?
                if written_full_reg_set.contains(&reg.full_register()) {
                    let lhs_var = LocationBuilder::new().register(reg.full_register()).build();
                    if reg.size() == 4 {
                        // TODO: zero-extend expr
                        // trace!("zero-extend for 32-bit registers {:?}", reg);
                        // semantics.push(Proof::Rel(Relationship {
                        //     relationship: BinaryRelation::Lt,
                        //     left_hand_side: Expr::Var(lhs_var),
                        //     right_hand_side: Expr::Imm(Imm::from(0x100000000 as u64)),
                        // }));
                    } else {
                        trace!("havoc register {:?}", reg);
                        semantics.push(Assignment::new(
                            lhs_var,
                            Expr::Any(lhs_var.get_sort().into()),
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    // TODO: also do it for memory addresses
    Ok(semantics)
}

// Load/Store related

#[cfg(feature = "wasmsfi")]
fn cmovae_lucet(_ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/cmovcc
    // 1st operand: destination; 2nd operand: source
    // NOTE: Read from memory => havoc destination
    // let dst = location_operand(ins, 0)?;
    // Note here that we assume CMOV will never take!!!!!
    // let src = expr_operand(ins, 0)?;
    // let mut asgns = Vec::new();
    // To be consistent with VeriWASM, we just use an empty semantics
    // asgns.push(Assignment {
    //     left_hand_side: dst,
    //     right_hand_side: src,
    // });
    debug!("Semantics: empty for CMOVae");
    Ok(Vec::new())
}

fn mov(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/mov
    // https://www.felixcloutier.com/x86/movd:movq

    // 1st operand: destination; 2nd operand: source
    // NOTE: Read from memory => havoc destination
    // debug!("ins {:?}", ins);
    let dst = location_operand(ins, 0)?;
    let mut src = expr_operand(ins, 1)?;

    // TODO: handle movsxd
    if Mnemonic::Movsxd == ins.mnemonic() {
        match src {
            Expr::Var(v) => match v {
                Location::Memory(m) => {
                    let mut m = m.clone();
                    m.size = dst.get_sort().into();
                    src = Location::Memory(m).into();
                }
                _ => {}
            },
            _ => {}
        }
    }
    let mut asgns = Vec::new();
    asgns.push(Assignment::new(dst, src));

    debug!("Semantics: {:?}", asgns);
    Ok(asgns)
}

fn lea(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/lea
    // 1st operand: destination; 2nd operand: source
    // NOTE: Read from memory => havoc destination
    let dst = location_operand(ins, 0)?;
    let src = expr_operand(ins, 1)?;
    let ea = if let GenericExpr::Var(GenericLocation::Memory(m)) = src {
        m.take_address()?
    } else {
        return Err(anyhow!("Not loading from memory address!"));
    };
    let mut asgns = Vec::new();
    asgns.push(Assignment::new(dst, ea));

    // debug!("Semantics: {:?}", asgns);
    Ok(asgns)
}

// Stack Operations

fn push(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/push
    // https://www.felixcloutier.com/x86/pusha:pushad
    // https://www.felixcloutier.com/x86/pushf:pushfd:pushfq
    // TODO: push partial register exists??
    let var = location_operand(ins, 0)?;
    let mut asgns = Vec::new();
    let rsp_var = Location::Register(Register::RSP);
    // Stack pointer memory update
    asgns.push(Assignment::new(
        MemCellBuilder::new()
            .base_reg(Register::RSP)
            .displacement(-8)
            .build()
            .into(),
        var.into(),
    ));
    // RSP minus
    asgns.push(Assignment::new(
        rsp_var.clone(),
        expr!(
            rsp_var.clone().into(),
            bv!("bvsub"),
            Imm::from(8 as u64).into()
        ),
    ));
    Ok(asgns)
}

fn pop(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/pop
    let var = location_operand(ins, 0)?;
    let mut asgns = Vec::new();
    let rsp_var = Location::Register(Register::RSP);
    // pop dst update
    asgns.push(Assignment::new(var, rsp_var.to_memvar()?.into()));
    // RSP plus

    asgns.push(Assignment::new(
        rsp_var.clone(),
        expr!(
            rsp_var.clone().into(),
            bv!("bvadd"),
            Imm::from(8 as u64).into()
        ),
    ));
    Ok(asgns)
}

// Control Flow

fn call(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/call

    // TODO Add push return address check for stack boundary.
    trace!("Semantics: call");
    let mut asgns = Vec::new();
    let dst = expr_operand(ins, 0)?;
    // Since the call to the address is outside the scope of a function, we currently omit that
    asgns.push(Assignment::new(Register::RIP.into(), dst));
    Ok(asgns)
}

fn ret(_ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/ret

    // RET currently bears an empty semantics.
    trace!("Semantics: ret");
    let mut asgns = Vec::new();
    let rsp_var = Location::Register(Register::RSP);
    // Since the returned place is outside the scope of a function, we currently omit that
    asgns.push(Assignment::new(
        rsp_var.clone(),
        expr!(rsp_var.into(), bv!("bvadd"), Imm::from(8 as u64).into()),
    ));
    Ok(asgns)
}

// Arithmetic Operations

fn xor(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/add
    // 1st operand: destination; 2nd operand: source
    // println!("DEBUG: {:?}", ins);
    let mut asgns = Vec::new();
    let dst = location_operand(ins, 0)?;
    // short circuit for xor %reg, %reg

    if let Ok(src) = location_operand(ins, 1) && src == dst {
        asgns.push(Assignment::new(dst,
            Imm::from(0).convert(ValSize::from(dst.infer_sort()?)).into(),
        ));
    } else {
        let src = expr_operand(ins, 1)?;
        asgns.push(Assignment::new(dst, expr!(dst.into(), bv!("bvxor"), src)));
    }

    debug!("Semantics: {:?}", asgns);
    Ok(asgns)
}

fn add(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/add
    // 1st operand: destination; 2nd operand: source
    // println!("DEBUG: {:?}", ins);
    let dst = location_operand(ins, 0)?;
    let src = expr_operand(ins, 1)?;
    let mut asgns = Vec::new();
    asgns.push(Assignment::new(dst, expr!(dst.into(), bv!("bvadd"), src)));

    debug!("Semantics: {:?}", asgns);
    Ok(asgns)
}

fn sub(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/sub
    // 1st operand: destination; 2nd operand: source
    // println!("DEBUG: {:?}", ins);
    let dst = location_operand(ins, 0)?;
    let src = expr_operand(ins, 1)?;
    let mut asgns = Vec::new();
    asgns.push(Assignment::new(dst, expr!(dst.into(), bv!("bvsub"), src)));

    debug!("Semantics: {:?}", asgns);
    Ok(asgns)
}

fn shl(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/sal:sar:shl:shr
    // 1st operand: destination; 2nd operand: source
    // println!("DEBUG: {:?}", ins);
    let dst = location_operand(ins, 0)?;
    let src = expr_operand(ins, 1)?;
    let mut asgns = Vec::new();
    let dst_sort = dst.infer_sort()?;
    asgns.push(Assignment::new(
        dst,
        expr!(
            dst.into(),
            bv!("bvshl"),
            src.infer_sort()?.cast(dst_sort)?(src)
        ),
    ));

    debug!("Semantics: {:?}", asgns);
    Ok(asgns)
}

fn jcc(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/jcc
    let mut asgns = Vec::new();
    // TODO This part needs to be completed for different kinds of Jcc
    // instructions, the flags will be different.
    match ins.mnemonic() {
        Mnemonic::Jae => {
            // println!("Jae: {:x?}", ins);
            asgns.push(Assignment::new(
                Register::RIP.into(),
                Expr::Ite(
                    Box::new(Location::Flag(Flags::CF).into()),
                    Box::new(Imm::from(ins.next_ip()).into()),
                    Box::new(Imm::from(ins.memory_displacement64()).into()),
                ),
            ));
        }
        Mnemonic::Jne => {
            // println!("Jne: {:x?}", ins);
            asgns.push(Assignment::new(
                Register::RIP.into(),
                Expr::Ite(
                    Box::new(Location::Flag(Flags::ZF).into()),
                    Box::new(Imm::from(ins.next_ip()).into()),
                    Box::new(Imm::from(ins.memory_displacement64()).into()),
                ),
            ));
        }
        _ => {}
    }
    Ok(asgns)
}

fn cmp(ins: &Instruction) -> Result<Vec<Assignment>> {
    // https://www.felixcloutier.com/x86/cmp
    // println!("DEBUG: {:x?}", ins);
    let mut asgns = Vec::new();
    // setting CF
    asgns.push(Assignment::new(
        Location::Flag(Flags::CF),
        expr!(expr_operand(ins, 0)?, bv!("bvult"), expr_operand(ins, 1)?),
    ));
    // setting ZF
    asgns.push(Assignment::new(
        Location::Flag(Flags::ZF),
        expr!(expr_operand(ins, 0)?, bv!("="), expr_operand(ins, 1)?),
    ));
    Ok(asgns)
}

pub fn expr_operand(ins: &Instruction, operand_idx: u32) -> Result<Expr> {
    match ins.op_kind(operand_idx) {
        OpKind::Memory | OpKind::Register => {
            let var = location_operand(ins, operand_idx)?;
            Ok(var.into())
        }
        OpKind::Immediate8 => Ok(Imm::from(ins.immediate8() as i8).into()),
        OpKind::Immediate16 => Ok(Imm::from(ins.immediate16() as i16).into()),
        OpKind::Immediate32 => Ok(Imm::from(ins.immediate32() as i32).into()),
        OpKind::Immediate64 => Ok(Imm::from(ins.immediate64()).into()),
        OpKind::Immediate8to32 => Ok(Imm::from(ins.immediate8to32()).into()),
        OpKind::Immediate8to64 => Ok(Imm::from(ins.immediate8to64()).into()),
        OpKind::Immediate32to64 => Ok(Imm::from(ins.immediate32to64()).into()),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Ok(Imm::from(ins.near_branch_target()).into())
        }
        ud => return Err(anyhow::anyhow!("Unsupported expr operand kind {:?}", ud)),
    }
}

pub fn location_operand(ins: &Instruction, operand_idx: u32) -> Result<Location> {
    match ins.op_kind(operand_idx) {
        OpKind::Register => {
            trace!("Register operand at loc {} of ins {:x?}", operand_idx, ins);
            Ok(Location::Register(ins.op_register(operand_idx)))
        }
        OpKind::Memory => {
            let vb = LocationBuilder::new();
            trace!(
                "Memory operand at loc {} of ins {:x?}, memsize: {:?}",
                operand_idx,
                ins,
                ins.memory_size()
            );
            let mut mcb = MemCellBuilder::new();
            mcb = if ins.is_ip_rel_memory_operand() {
                mcb.displacement(ins.memory_displacement64() as i64)
                    .size(ValSize::try_from(ins.memory_size().size()).unwrap_or(ValSize::Size64))
            } else {
                mcb.base_reg(ins.memory_base())
                    .displacement(ins.memory_displacement64() as i64)
                    .index_reg(ins.memory_index())
                    .scale(Some(ins.memory_index_scale().try_into().unwrap()))
                    // LEA case: memorysize is unknow, so we set it default to 64 bits
                    .size(ValSize::try_from(ins.memory_size().size()).unwrap_or(ValSize::Size64))
            };
            Ok(vb.memcell(mcb.build()).build())
        }
        ud => Err(anyhow::anyhow!("Unsupported lhs operand kind {:?}", ud)),
    }
}

// fn _get_var_size(size: usize) -> ValSize {
//     match size {
//         1 => ValSize::Size8,
//         2 => ValSize::Size16,
//         4 => ValSize::Size32,
//         8 => ValSize::Size64,
//         _ => unimplemented!(),
//     }
// }

#[cfg(test)]
mod semantics_lifting_test {
    use super::*;
    use crate::dis::disasm_code;
    use parser::*;

    fn dis_ins(data: &[u8]) -> iced_asm::Instruction {
        disasm_code(data, Some(0))[0]
    }

    #[test]
    fn test_push_write_dests() {
        // 55                   	push   %rbp
        let asm: &[u8] = &[0x55];
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        let write_dests = get_write_destinations(&ins);
        println!("Sem: {:#x?}", sem);
        println!("Write dests: {:#x?}", write_dests);
    }

    #[test]
    fn test_pop_write_dests() {
        // 5d                   	pop    %rbp
        let asm: &[u8] = &[0x5d];
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        let write_dests = get_write_destinations(&ins);
        let read_sources = get_read_sources(&ins);
        println!("Sem: {:#x?}", sem);
        println!("Write dests: {:#x?}", write_dests);
        println!("Read sources: {:#x?}", read_sources);
    }

    #[test]
    fn test_push1() {
        // env_logger::Builder::from_env(Env::default().default_filter_or("debug")).try_init();
        // Problem: this is not the same as objdump result, see proof_checker/testdump.s:20
        // If we stick with the disassembly shown in objdump, we must update ip first in instructions to get a consistent result
        let asm: &[u8] = &[0xff, 0x35, 0xe2, 0x2f, 0x00, 0x00]; // pushq 0x2fe2(%rip)
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        println!("{:#x?}", sem);
        // formatter.options_mut().set_uppercase_mnemonics(true);
        // NOTE: iced is using the OLD RIP in addressing
        // let proof = parse_proof_str("q[rsp] := q[rip + 0x2fe8]").unwrap();
        // assert_eq!(validate_proof(&ins, &proof).unwrap(), true);
    }

    #[test]
    fn test_push2_ok() {
        let asm: &[u8] = &[0x55]; // push %rbp
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        let proof1 = parse_proof_str("q[rsp - 0x8] := rbp").unwrap();
        let proof2 = parse_proof_str("rsp := bvsub rsp 0x0000000000000008").unwrap();
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
        assert_eq!(sem.assignments[1], proof2.try_into().unwrap());
    }

    #[test]
    fn test_mov1_ok() {
        let asm: &[u8] = &[0x4c, 0x89, 0x6c, 0x24, 0x08]; // mov %r13,0x8(%rsp)
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        let proof1 = parse_proof_str("q[rsp + 0x0000000000000008] := r13").unwrap();
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }

    #[test]
    fn test_mov2_ok() {
        let asm: &[u8] = &[0x48, 0x8b, 0x47, 0xf8]; // mov -0x8(%rdi),%rax
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        println!("{:#x?}", sem);
        let proof1 = parse_proof_str("rax := q[rdi + 0xfffffffffffffff8]").unwrap();
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }

    #[test]
    fn test_mov3_ok() {
        // let _ = env_logger::Builder::from_env(Env::default().default_filter_or("debug")).try_init();
        let asm: &[u8] = &[0x41, 0xb8, 0x00, 0x00, 0x40, 0x00]; // mov $0x400000,%r8d
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        let proof1 = parse_proof_str("r8 := 0x00400000").unwrap();
        // TODO: check this relationship!
        let _proof2 = parse_proof_str("bvult r8 0x0000000100000000").unwrap();
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }

    #[test]
    fn test_mov4_ok() {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
                .try_init();
        let asm: &[u8] = &[0x89, 0x37]; // mov    %esi,(%rdi)
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        println!("{:#x?}", sem);
        let proof1 = parse_proof_str("d[rdi] := (extract 31 0) esi").unwrap();
        println!("{:#x?}", proof1);
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }

    #[test]
    fn test_mov5_ok() {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
                .try_init();
        let asm: &[u8] = &[0x89, 0xd8]; // mov    %ebx, %eax
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        println!("{:#x?}", sem);
        let proof1 = parse_proof_str("rax := (extract 31 0) rbx").unwrap();
        println!("{:#x?}", proof1);
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }

    #[test]
    fn test_mov6_ok() {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
                .try_init();
        let asm: &[u8] = &[0xf2, 0x0f, 0x10, 0xc1]; // movsd  %xmm1,%xmm0
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        println!("{:#x?}", ins);
        let proof1 = parse_proof_str("xmm0 := xmm1").unwrap();
        println!("{:#x?}", proof1);
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }

    #[test]
    fn test_mov7_ok() {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
                .try_init();
        // 8b 05 25 92 00 00    mov    mov    0x9225(%rip),%eax        # 1539c <regmng+0x13c>
        let asm: &[u8] = &[0x8b, 0x05, 0x25, 0x92, 0x00, 0x00];
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        println!("{:#x?}", ins);
        let proof1 = parse_proof_str("xmm0 := xmm1").unwrap();
        println!("{:#x?}", proof1);
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }

    #[test]
    fn test_mov8_ok() {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .try_init();
        // cfb1:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
        let asm: &[u8] = &[0x48, 0x8b, 0x45, 0xf8];
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        println!("{:#x?}", sem);
    }

    #[test]
    fn test_movabs() {
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
                .try_init();
        // 39a7d:	48 be 9a 99 99 99 99 	movabs $0x199999999999999a,%rsi
        let asm: &[u8] = &[0x48, 0xbe, 0x9a, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x19];
        let ins = dis_ins(asm);
        println!("location operand 0: {:?}", location_operand(&ins, 0));
        let sem = lift_ins(&ins).unwrap();
        println!("{:#x?}", sem);
    }

    #[test]
    fn test_lea_ok() {
        let asm: &[u8] = &[0x48, 0x8d, 0x05, 0xc3, 0x2e, 0x01, 0x00]; // lea  0x12ec3(%rip)
        let ins = dis_ins(asm);
        let sem = lift_ins(&ins).unwrap();
        let proof1 = parse_proof_str("rax := 0x0000000000012eca").unwrap();
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }

    #[test]
    fn test_add1_ok() {
        let asm: &[u8] = &[0x83, 0xc6, 0xf0]; // add    $0xfffffff0,%esi
        let ins = dis_ins(asm);
        println!("{:#x?}", ins);
        let sem = lift_ins(&ins).unwrap();
        println!("SEM: {:#x?}", sem);
        // TODO: this is dangerous! the type(negativity) information is lost
        let proof1 = parse_proof_str("rsi := bvadd esi 0xfffffff0").unwrap();
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }

    #[test]
    fn test_shl_32_ok() {
        //    1f60d:   c1 e1 04                shl    $0x4,%ecx
        let asm = &[0xc1, 0xe1, 0x04];
        let ins = dis_ins(asm);
        println!("{:#x?}", ins);
        let sem = lift_ins(&ins).unwrap();
        println!("SEM: {:#x?}", sem);
        let proof1 = parse_proof_str("rcx := bvshl ecx 0x04").unwrap();
        assert_eq!(sem.assignments[0], proof1.try_into().unwrap());
    }
    #[test]
    fn test_fadd() {
        // Should not panic
        let _ =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
                .try_init();
        //    3a896:	d8 02                	fadds  (%rdx)
        let asm: &[u8] = &[0xd8, 0x02]; // fadd    (%rdx)
        let ins = dis_ins(asm);
        println!("{:#x?}", ins);
        let sem = lift_ins(&ins).unwrap();
        println!("SEM: {:#x?}", sem);
    }

    #[test]
    fn test_wild1() {
        let asm: &[u8] = &[0x83, 0xc7, 0xf0]; // add $0xfffffff0,%edi
        let _ins = dis_ins(asm);
        let _proof = parse_proof_str("bvult rdi 0x0000000100000000").unwrap();
    }
}
