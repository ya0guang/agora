use crate::dis::*;
use crate::policy::*;
use crate::semantics::*;
use crate::solve::*;
use crate::ssa::*;
use crate::validate::*;
use anyhow::Result;
// use disasm::{disasm_binary, disasm_code};
use std::collections::{BTreeMap, HashMap};

// The `dis_*` functions are not inside the TCB and should be removed in release!

// /// Wrapper of `iced_disasm_all`, avoiding using a iced decoder
// pub fn dis_hex(asm: &[u8], addr: u64) -> Result<Disassembled> {
//     let mut dis = BTreeMap::new();
//     for i in disasm_code(asm, Some(addr)) {
//         dis.insert(i.ip(), i);
//     }
//     let dis: BTreeMap<u64, iced_asm::Instruction> =
//         serde_json::from_str(&serde_json::to_string(&dis)?)?;
//     Ok(dis)
// }

// pub fn dis_funcs(path: &std::path::Path) -> Result<HashMap<String, Disassembled>> {
//     let dis = disasm_binary(path)?;
//     let dis: HashMap<String, Disassembled> = serde_json::from_str(&serde_json::to_string(&dis)?)?;
//     Ok(dis)
// }

// pub fn dis_all(data: &[u8], ip: Option<u64>) -> Result<Vec<iced_asm::Instruction>> {
//     let dis = disasm_code(data, ip);
//     let dis: Vec<iced_asm::Instruction> = serde_json::from_str(&serde_json::to_string(&dis)?)?;
//     Ok(dis)
// }

macro_rules! measure_time {
    ($code:expr, $time_cost:expr) => {{
        let start = std::time::Instant::now();
        let ret = $code;
        let elapsed = start.elapsed();
        $time_cost.push(elapsed.as_secs_f64());
        ret
    }};
}

pub fn run_func(
    func_name: &String,
    raw: &[u8],
    dis: &Disassembled,
    proof: &HashMap<u64, Vec<ir::Proof>>,
    verifier: &Verifier,
) -> Result<Vec<f64>> {
    let mut time_cost = vec![];

    println!("Working on function {}", func_name);
    // 1. lift semantics in proof IR
    let lifted_sem = measure_time!(lift(dis.iter())?, &mut time_cost);

    // 2. CFG construction
    println!("CFG working on function {}", func_name);
    let cfi = measure_time!(cfg_analysis(raw, &dis)?, &mut time_cost);

    //3. Rewrite IR in SSA form
    println!("SSA working on function {}", func_name);

    let ssa_sem = measure_time!(ssa(&cfi, &dis, &lifted_sem, &verifier)?, &mut time_cost);
    // debug!("Finished SSA construction, semantics: {:#?}", ssa_semantics);

    // 4. Proof Validation and Transcription
    println!("processing proof for function {}", func_name);
    let total_proof = measure_time!(process_proof(&dis, &ssa_sem, &proof)?, &mut time_cost);
    // trace!("Total proof: {:#x?}", total_proof);

    let mut func_constraints = BTreeMap::new();
    for (addr, tp) in total_proof.iter() {
        func_constraints.insert(*addr, Constraints::init(tp));
    }

    // 5. Insert assertions according to the policy
    measure_time!(
        verifier.verify(&ssa_sem, &dis, &total_proof, &mut func_constraints, &cfi)?,
        &mut time_cost
    );

    // 6. form SMT formulas (instantiate policy)
    measure_time!(
        solve_function(&func_constraints, &ssa_sem, func_name, &cfi, &verifier)?,
        &mut time_cost
    );

    Ok(time_cost)
}
