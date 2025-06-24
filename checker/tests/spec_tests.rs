use anyhow::{anyhow, Result};
use checker::dis::{disasm_binary, resolve_text_symbols};
use checker::{
    policy::{BinaryType, Policy, Verifier},
    utils::*,
};
use parser::parse;
use std::{fs, path::Path};

#[test]
fn test_astar_o0() {
    let avoid_functions = vec![];
    assert_eq!(
        run_test("astar_O0", &avoid_functions).unwrap(),
        Vec::<String>::new()
    );
}

#[test]
fn test_astar_o3() {
    let avoid_functions = vec![];
    assert_eq!(
        run_test("astar_O3", &avoid_functions).unwrap(),
        Vec::<String>::new()
    );
}

fn run_test(spec_name: &str, avoid_functions: &Vec<&str>) -> Result<Vec<String>> {
    // env_logger::Builder::from_env(Env::default().default_filter_or("warn")).try_init()?;
    let proj_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let executable_file = proj_dir.join(format!("../resources/spec2006/{}", spec_name));
    let bin = fs::read(&executable_file).expect("Could not read binary file");
    let sym_rawdata = resolve_text_symbols(&bin)?;
    let verifier = Verifier::new(Policy::WasmSFI, BinaryType::Lucet, bin, false);

    gen_resources(&executable_file, proj_dir)?;
    std::env::set_current_dir(proj_dir.join("../eval").join(spec_name))?;

    let proof_file = proj_dir.join(format!("../eval/{0}/{0}.prf", spec_name));
    let proof_input = std::fs::read_to_string(proof_file).expect("Could not read proof file");
    let proof = parse(&proof_input)?;
    let whole_dis = disasm_binary(&executable_file)?;
    let mut error_funcs = Vec::new();
    for (func_name, dis) in whole_dis {
        if avoid_functions.contains(&func_name.as_str()) {
            continue;
        } else {
            if run_func(
                &func_name,
                &sym_rawdata.get(&func_name).unwrap().data,
                &dis,
                &proof,
                &verifier,
            )
            .is_err()
            {
                error_funcs.push(func_name);
            }
        }
    }
    Ok(error_funcs)
}

fn gen_resources(executable_file: &Path, proj_dir: &Path) -> Result<()> {
    let script = proj_dir.join("../eval/run_workflow.py");
    let args = [
        "--no-build",
        "--no-check",
        "-e",
        executable_file.to_str().unwrap(),
    ];
    let code = std::process::Command::new(script)
        .args(args)
        .status()?
        .code()
        .unwrap();
    if code != 0 {
        return Err(anyhow!("Failed to generate resources"));
    }
    Ok(())
}
