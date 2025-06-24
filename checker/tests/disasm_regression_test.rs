use anyhow::anyhow;
use anyhow::Result;
use checker::dis::{disasm_code, MySymbolResolver};
use env_logger::Env;
use iced_asm::Encoder;
use iced_asm::Instruction;
use log::{debug, error, trace, warn};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::path::PathBuf;

#[test]
fn test_reasm_main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("warn")).try_init()?;
    let proj_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let executable_file = proj_dir.join("../resources/brloop/brloop");
    let (dis, bin) = test_disasm(&executable_file)?;

    for (fun_name, fun_dis) in dis.iter() {
        println!("Reassembling function {}", fun_name);
        let fun_bin = bin.get(fun_name).unwrap();
        let mut reassembled = Vec::new();
        for (addr, inst) in fun_dis.iter() {
            let mut encoder = Encoder::new(64);
            match encoder.encode(inst, *addr) {
                Ok(_) => {
                    let mut buffer = encoder.take_buffer();
                    trace!(
                        "Reassembling instruction at addr {:#x}: {:x?}, encodedd as {:x?}",
                        addr,
                        inst,
                        buffer
                    );
                    reassembled.append(&mut buffer);
                }
                Err(e) => {
                    error!(
                        "Failed to reassemble instruction at addr {:#x}: {:x?}, error: {}",
                        addr, inst, e
                    );
                    continue;
                }
            }
        }
        match compare(&reassembled, fun_bin) {
            Ok(_) => {
                debug!("Reassembled function {} matches original binary", fun_name);
            }
            Err(e) => {
                warn!(
                    "Reassembled function {} differs from original binary: {}",
                    fun_name, e
                );
            }
        }
    }
    Ok(())
}

fn compare(reassembled: &[u8], fun_bin: &[u8]) -> Result<()> {
    if reassembled.len() != fun_bin.len() {
        warn!(
            "Reassembled binary length {} != original binary length {}",
            reassembled.len(),
            fun_bin.len()
        )
    }
    let len = std::cmp::min(reassembled.len(), fun_bin.len());
    for i in 0..len {
        if reassembled[i] != fun_bin[i] {
            return Err(anyhow!("Mismatch found at offset {:x}", i));
        }
    }
    Ok(())
}

pub fn test_disasm(
    path: &PathBuf,
) -> Result<(
    HashMap<String, BTreeMap<u64, Instruction>>,
    HashMap<String, Vec<u8>>,
)> {
    let bin_data = std::fs::read(path)?;
    let obj_file = object::File::parse(&*bin_data)?;

    let mut sym_map = HashMap::<u64, String>::new();
    for sym in obj_file.symbols() {
        if let Ok(name) = sym.name() {
            sym_map.insert(sym.address(), name.to_string());
        }
    }
    let _resolver = Box::new(MySymbolResolver { map: sym_map });
    // let mut formatter = IntelFormatter::with_options(Some(resolver), None);

    let functions = obj_file
        .symbols()
        .filter(|sym| sym.kind() == SymbolKind::Text);

    let mut disassmbled = HashMap::new();
    let mut function_bin = HashMap::new();

    // disassemble symbols in Text section(s)
    for sym in functions {
        let mut output = BTreeMap::new();
        // println!("Symbol: {:?}", sym);
        let sym_section = match sym.section_index() {
            Some(i) => obj_file.section_by_index(i)?,
            None => continue,
        };
        // println!("Section: {:?}", sym_section);
        let sym_addr = sym.address();
        let sym_size = sym.size();
        if sym_size == 0 {
            // TODO: rectify symbol sizes, current size is not accurate!
            continue;
        }
        trace!("Disassembling symbol: {:?} @ {:#x}", sym.name(), sym_addr);
        let sym_bin = sym_section.data_range(sym_addr, sym_size)?.unwrap();

        let mut pos = sym_addr;
        for i in disasm_code(&sym_bin, Some(sym_addr)) {
            let mut _temp_out = String::new();
            // formatter.format(&i, &mut temp_out);
            // trace!("0x{:x}: {}", pos, temp_out);
            output.insert(pos, i);
            pos += i.len() as u64;
        }

        disassmbled.insert(sym.name().unwrap().to_string(), output);
        function_bin.insert(sym.name().unwrap().to_string(), sym_bin.to_vec());
    }

    Ok((disassmbled, function_bin))
}
