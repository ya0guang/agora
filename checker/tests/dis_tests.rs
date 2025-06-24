use anyhow::{Ok, Result};
use checker::dis::resolve_text_symbols;
use checker::dis::*;
use env_logger::Env;
use std::path::Path;

#[test]
fn test_cfg_main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("error")).init();
    // change the return v
    let _ = test_cfg("branch_9")?;
    let _ = test_cfg("forloop_10")?;
    let _ = test_cfg("whileloop_11")?;
    let _ = test_cfg("if_test_12")?;
    let cfi = test_cfg("main_13")?;
    println!("{:#x?}", cfi);
    Ok(())
}

fn test_cfg(func_name: &str) -> Result<ControlFlowInfo> {
    let proj_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bin_file = proj_dir.join("../resources/brloop/brloop");
    let bin = std::fs::read(&bin_file).expect("Could not read binary file");
    let sym_rawdata = resolve_text_symbols(&bin)?;
    let disassembled = disasm_binary(&bin_file)?
        .remove(func_name)
        .ok_or(anyhow::anyhow!("Function `{}` not found", &func_name))?;
    let cfi = cfg_analysis(&sym_rawdata.get(func_name).unwrap().data, &disassembled)?;
    Ok(cfi)
}
