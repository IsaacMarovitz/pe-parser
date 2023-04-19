use std::io::{Error, ErrorKind};
use std::{env, fs};
use pe_parser::pe::parse_portable_executable;

fn main() -> Result<(), Error> {
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    println!("PE Parser - Version {}", VERSION);
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