extern crate pest;

use ir::OutputPrf;
use parser::parse::parse;
use std::fs;

#[test]
fn parser_test() {
    use env_logger::Env;

    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();
    let path = "sample.prf";
    let proof_input = fs::read_to_string(path).expect("Could not read proof file");
    let proof = parse(&proof_input).unwrap();

    println!("Debug print of proof:");
    for line in &proof {
        println!("{:?}", line);
    }

    println!("`prf` format of proof:");
    for (line, proofs) in &proof {
        for p in proofs {
            println!("0x{:x} {}", line, p.output_prf());
        }
    }
}
