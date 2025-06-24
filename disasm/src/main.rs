use clap::Parser;
use disasm::disasm_binary;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Args {
    /// The input path of binary ELF file
    #[clap(value_parser)]
    input_bin: PathBuf,
    /// The output path of disassembled .json file
    #[clap(value_parser, default_value = "disasm.json")]
    output_json: PathBuf,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    let dis = disasm_binary(&args.input_bin).unwrap();
    let dis_ser = serde_json::to_string(&dis).unwrap();
    fs::write(&args.output_json, dis_ser).unwrap();
}
