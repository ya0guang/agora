use anyhow::Ok;
use anyhow::Result;
use checker::dis::resolve_text_symbols;
use checker::dis::*;
use checker::policy::Verifier;
use checker::semantics::*;
use checker::ssa::*;
use env_logger::Env;
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn test_ssa_main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();
    let func_names = vec!["branch_9", "forloop_10", "whileloop_11"];
    func_names.iter().try_for_each(|func_name| {
        let _ = test_ssa_brloop(func_name)?;
        Ok(())
    })?;
    // println!("ssa:\n{:#X?}", result);
    Ok(())
}

fn test_ssa_brloop(func_name: &str) -> Result<FuncSSA> {
    let proj_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bin_file = proj_dir.join("../resources/brloop/brloop");
    let bin = std::fs::read(&bin_file).expect("Could not read binary file");
    let sym_rawdata = resolve_text_symbols(&bin)?;
    let disassembled = disasm_binary(&bin_file)?
        .remove(func_name)
        .ok_or(anyhow::anyhow!("Function `{}` not found", &func_name))?;
    let semantics = lift(disassembled.iter())?;
    let mut semantics_btree = BTreeMap::new();
    for (addr, sem) in semantics.iter() {
        semantics_btree.insert(*addr, sem.clone());
    }
    // println!("semantics:\n{:#X?}", semantics_btree);
    let cfi = cfg_analysis(&sym_rawdata.get(func_name).unwrap().data, &disassembled)?;
    let ssa = ssa(&cfi, &disassembled, &semantics, &Verifier::dummy())?;
    Ok(ssa)
}
