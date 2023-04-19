pub mod scribe;
pub mod coff;
pub mod optional;
pub mod section;
pub mod pe;

use std::io::{Error, ErrorKind};
use std::{env, fs};
use crate::coff::coff_file_header;
use crate::pe::{parse_portable_executable};
use crate::section::parse_section_table;

fn main() -> Result<(), Error> {
    println!("PE Parser - Version 0.1.0");
    println!("=========================\n");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(Error::new(ErrorKind::InvalidInput, "No file passed to parse!"));
    }

    let file_path = &args[1];
    let binary = fs::read(file_path)
        .expect("Failed to read file");

    let pe = parse_portable_executable(binary.as_slice())
        .expect("Failed to parse Portable Executable!");

    print!("{}", pe);

    Ok(())
}