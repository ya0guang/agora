use anyhow::Ok;
use anyhow::Result;
use checker::dis::*;
use checker::policy::*;
use checker::semantics::*;
use checker::solve::*;
use checker::ssa::*;
use checker::utils::*;
use checker::validate::*;
use log::trace;
use parser::parse;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// if there exists rels: => feed assignments and check for all rel in rels, (unsat !rel)
/// if there exists no rels: => only feed the assignments already encoded

// #[test]
fn _test_new() {
    // 2420:	55                   	push   %rbp
    // 2421:	48 89 e5             	mov    %rsp,%rbp
    // 2424:	48 83 ec 10          	sub    $0x10,%rsp
    // 2428:	4c 89 24 24          	mov    %r12,(%rsp)
    // 242c:	4c 89 6c 24 08       	mov    %r13,0x8(%rsp)
    // 2431:	49 89 fc             	mov    %rdi,%r12
    // 2434:	49 8b 74 24 e0       	mov    -0x20(%r12),%rsi     -> -0x20(%r12)  = GLOBALBASE => %rsi
    // 2439:	44 8b 2e             	mov    (%rsi),%r13d         -> %r13d        = *uint GLOBAL[0]
    // 243c:	4c 89 ee             	mov    %r13,%rsi            -> GLOBAL[0]    = %rsi
    // 243f:	83 c6 f0             	add    $0xfffffff0,%esi     -> %rsi         = %rsi - 0x10
    //                                  RSI =  ((RSI & 0xFFFFFFFF) + 0xFFFFFFF0) & 0xFFFFFFFF
    //                                  RSI <= 0xFFFFFFFF
    // 2442:	49 8b 7c 24 e0       	mov    -0x20(%r12),%rdi     -> -0x20(%r12)  = GLOBALBASE => %rdi
    // 2447:	89 37                	mov    %esi,(%rdi)
    let asm: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0x4c, 0x89, 0x24, 0x24, 0x4c, 0x89, 0x6c,
        0x24, 0x08, 0x49, 0x89, 0xfc, 0x49, 0x8b, 0x74, 0x24, 0xe0, 0x44, 0x8b, 0x2e, 0x4c, 0x89,
        0xee, 0x83, 0xc6, 0xf0, 0x49, 0x8b, 0x7c, 0x24, 0xe0, 0x89, 0x37,
    ];
    let addr = 0x2420;
    let proj_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let proof_file = proj_dir.join(format!("../resources/brloop/{}.prf", "brloop"));
    let _ = run_membound_test(asm, addr, &proof_file).unwrap();
}

#[test]
fn test_debug() {
    // 401f:   48 c1 e7 04             shl    $0x4,%rdi
    let asm: &[u8] = &[
        0x48, 0xc1, 0xe7, 0x04, // shl    $0x4,%rdi
    ];
    let addr = 0x401f;
    let proj_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let proof_file = proj_dir.join(format!("../resources/spec2006/{}.prf", "__uflow_99"));
    let _ = run_membound_test(asm, addr, &proof_file).unwrap();
}

// fn run_indirectcall_test(asm: &[u8], addr: u64, proof: &PathBuf) -> Result<()> {
//     use log::LevelFilter;
//     let _ = env_logger::Builder::new()
//         .filter(None, LevelFilter::Trace)
//         .filter(Some("ir"), LevelFilter::Warn)
//         .filter(Some("parser"), LevelFilter::Off)
//         .try_init();
//     let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
//         .try_init();

//     let dis = dis_hex(asm, addr)?;

//     let lifted_sem = lift(dis.iter())?;
//     println!("lifted: {:#X?}", lifted_sem);
//     let cfi = cfg_analysis(&asm, &dis)?;
//     let ssa_sem = ssa(&cfi, &dis, &lifted_sem, &Verifier::default())?;
//     // println!("reaching def: {:#X?}", ssa_sem.reaching_def_graph);
//     let proof_input = std::fs::read_to_string(&proof)?;
//     let proof = parse(&proof_input)?;
//     let total_proof = process_proof(&dis, &ssa_sem, &proof)?;
//     trace!("total proof: {:#X?}", total_proof);
//     let mut constraints = BTreeMap::new();
//     for (addr, proof) in total_proof.iter() {
//         constraints.insert(*addr, Constraints::init(proof));
//     }
//     let matcher = IndirectCallSafe::new();

//     matcher.match_function(&ssa_sem, &dis, &total_proof, &mut constraints)?;

//     // println!("constraints: {:#X?}", constraints);

//     solve_function(&constraints, &ssa_sem, &"test".to_string(), &cfi)?;

//     Ok(())
// }

fn run_membound_test(asm: &[u8], addr: u64, proof: &PathBuf) -> Result<()> {
    use log::LevelFilter;
    let _ = env_logger::Builder::new()
        .filter(None, LevelFilter::Trace)
        .filter(Some("ir"), LevelFilter::Warn)
        .filter(Some("parser"), LevelFilter::Off)
        .try_init();
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
        .try_init();

    let dis = disasm_block(asm, addr);

    let lifted_sem = lift(dis.iter())?;
    println!("lifted: {:#X?}", lifted_sem);
    let cfi = cfg_analysis(&asm, &dis)?;
    let ssa_sem = ssa(&cfi, &dis, &lifted_sem, &Verifier::dummy())?;
    // println!("reaching def: {:#X?}", ssa_sem.reaching_def_graph);
    let proof_input = std::fs::read_to_string(&proof)?;
    let proof = parse(&proof_input)?;
    let total_proof = process_proof(&dis, &ssa_sem, &proof)?;
    trace!("total proof: {:#X?}", total_proof);
    let mut constraints = BTreeMap::new();
    for (addr, proof) in total_proof.iter() {
        constraints.insert(*addr, Constraints::init(proof));
    }
    let matcher = MemAccessBounded::new(&ssa_sem);

    matcher.match_function(&ssa_sem, &dis, &total_proof, &mut constraints, &cfi)?;

    // println!("constraints: {:#X?}", constraints);

    solve_function(
        &constraints,
        &ssa_sem,
        &"test".to_string(),
        &cfi,
        &Verifier::dummy(),
    )?;

    Ok(())
}
