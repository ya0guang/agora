use clap::Parser;
use loaders::types::{ExecutableType, VwArch};
use std::path::PathBuf;
use std::str::FromStr;
use veriwasm::loaders;
use veriwasm::runner::*;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Args {
    /// path to native Wasm module to validate
    #[clap(short = 'i', value_parser)]
    module_path: PathBuf,
    /// Number of parallel threads (default 1)
    #[clap(value_parser)]
    jobs: Option<u32>,
    /// Path to output stats file
    #[clap(value_parser)]
    output: Option<String>,
    /// Single function to process (rather than whole module)
    #[clap(short, long, value_parser)]
    func: Option<String>,
    /// Format of the executable (lucet | wasmtime)
    #[clap(short = 'c', long, value_parser)]
    format: Option<String>,
    /// Architecture of the executable (x64 | aarch64)
    #[clap(long, value_parser)]
    arch: Option<String>,
    /// Disable stack checks
    #[clap(long, action)]
    disable_stack_checks: bool,
    /// Disable linear memory checks
    #[clap(long, action)]
    disable_linear_mem_checks: bool,
    /// disable_call_checks
    #[clap(long, action)]
    disable_call_checks: bool,
    /// enable_zero_cost_checks
    #[clap(long, action)]
    enable_zero_cost_checks: bool,
    /// strict
    #[clap(long, action)]
    strict: bool,
}

fn main() {
    let _ = env_logger::try_init();
    let args = Args::parse();

    let module_path = args.module_path;
    let num_jobs = args.jobs.unwrap_or(1);
    let only_func = args.func;
    let executable_type =
        ExecutableType::from_str(&args.format.unwrap_or(String::from("lucet"))).unwrap();
    let arch = VwArch::from_str(&args.arch.unwrap_or(String::from("x64"))).unwrap();

    let has_output = if args.output.is_some() { true } else { false };

    let active_passes = PassConfig {
        stack: !args.disable_stack_checks,
        linear_mem: !args.disable_linear_mem_checks,
        call: !args.disable_call_checks,
        zero_cost: args.enable_zero_cost_checks,
    };

    let config = Config {
        module_path: module_path.into_os_string().into_string().unwrap(),
        _num_jobs: num_jobs,
        output_path: args.output.unwrap_or("".to_string()),
        has_output: has_output,
        only_func,
        executable_type,
        active_passes,
        arch,
        strict: args.strict,
    };

    run(config);
}
