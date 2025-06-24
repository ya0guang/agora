use anyhow::Result;
use checker::dis::{disasm_binary, resolve_text_symbols};
use checker::policy::{BinaryType, Policy, Verifier};
use checker::utils::run_func;
use clap::Parser;
use parser::*;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

// Sometimes the stack size is not enough for the default 2MB
const STACK_SIZE: usize = 4 * 1024 * 1024;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Args {
    /// The input path of binary ELF file
    #[clap(value_parser)]
    input_bin: PathBuf,
    /// The input path of proof .prf file
    #[clap(value_parser)]
    input_proof: PathBuf,
    /// The input path of proof .prf file
    // #[clap(value_parser)]
    // input_disasm: PathBuf,
    /// The output path of time cost recording .json file
    #[clap(value_parser)]
    output_time_cost: Option<PathBuf>,
    /// Not invoker the SMT solver
    #[clap(short, long, action, default_value = "false")]
    solverless: bool,
    /// Specify the only function work on
    #[clap(short, long, value_parser)]
    focused_functions: Option<Vec<String>>,
    /// Specify the functions that are avoided
    #[clap(short, long, value_parser)]
    avoid_functions: Vec<String>,
    /// The specified policy [wasm, lfence]
    #[clap(short, long, default_value = "WasmSFI")]
    policy: Policy,
    /// The type of the verified binary [lucet, elf]
    #[clap(short, long, default_value = "lucet")]
    binary_type: BinaryType,
    /// The number of threads
    #[clap(short, long, default_value = "2")]
    threads: usize,
    // /// No proof mode
    // #[clap(long, action)]
    // proofless: bool,
}

fn main() {
    env_logger::init();
    let args = Args::parse();
    // if args.pass_first {
    //     run_pass_first(args).unwrap();
    // } else {
    run_funcions(args).unwrap();
    // }
}

fn run_funcions(mut args: Args) -> Result<()> {
    let binary = fs::read(&args.input_bin)?;
    let mut sym_rawdata = resolve_text_symbols(&binary)?;

    // Logging the information
    println!(
        "Verifying the binary {:?} using proof {:?}\nPolicy: {:?}",
        args.input_bin, args.input_proof, args.policy
    );

    // 0.0 disassemble the binary
    let mut dis_funcs = disasm_binary(&args.input_bin)?;

    // 0.1 parse proof
    let proof_input = fs::read_to_string(&args.input_proof).expect("Could not read proof file");
    let proof = parse(&proof_input)?;

    // filter out unfocused functions
    let mut focused_functions: BTreeSet<String> = match args.focused_functions {
        Some(func_names) => {
            // ensure that function names are in the ELF
            func_names.iter().for_each(|k| {
                if !dis_funcs.contains_key(k) {
                    panic!("focused function {} not found", k)
                }
            });
            BTreeSet::from_iter(func_names)
        }
        None => dis_funcs.keys().cloned().collect(),
    };

    // filter out avoid functions
    args.avoid_functions.push("lucet_probestack".to_string());
    // print the list of focused functions
    println!(
        "{} focused functions\n-----------------",
        focused_functions.len()
    );
    for func_name in focused_functions.iter() {
        println!("{}", func_name);
    }
    println!("-----------------\n");

    let verifier = Arc::new(Verifier::new(
        args.policy,
        args.binary_type,
        binary,
        args.solverless,
    ));

    let pool = threadpool::Builder::new()
        .num_threads(args.threads)
        .thread_stack_size(STACK_SIZE)
        .build();
    let (tx, rx) = std::sync::mpsc::channel();
    let proof = Arc::new(proof);
    let jobs = focused_functions.len();

    for func_name in focused_functions.into_iter() {
        let tx = tx.clone();
        let raw_data = sym_rawdata.remove(&func_name).unwrap().data;
        let dis = dis_funcs.remove(&func_name).unwrap();
        let p = proof.clone();
        let v = verifier.clone();
        pool.execute(move || {
            let time_cost = match run_func(&func_name, &raw_data, &dis, &p, &v) {
                Ok(time_cost) => {
                    let emoji = emojis::get_by_shortcode("heavy_check_mark").unwrap();
                    println!(
                        "\x1b[92m{}  Function {} is tentatively verified {}\x1b[0m",
                        emoji, func_name, emoji
                    );
                    time_cost
                }
                Err(e) => {
                    let emoji = emojis::get_by_shortcode("x").unwrap();
                    println!(
                        "\x1b[91m{}  Error in verification of func {}: {} {}\x1b[0m",
                        emoji, func_name, e, emoji
                    );
                    Vec::new()
                }
            };
            tx.send((func_name, time_cost))
                .expect("channel will be there waiting for the pool");
        });
    }
    let time_cost: HashMap<String, Vec<f64>> = rx
        .iter()
        .take(jobs)
        .filter(|(_, time_cost)| time_cost.len() > 0)
        .collect();
    if let Some(output_time_cost) = args.output_time_cost {
        fs::write(output_time_cost, serde_json::to_string(&time_cost)?)?;
    }

    println!("check [func_name].smt2 for the SMT formula to be published as the task");
    println!("if it generates no warnings, the proof should be verifiable by the bounty hunters");

    Ok(())
}
