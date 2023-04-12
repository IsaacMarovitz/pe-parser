mod scribe;
mod coff;
mod optional;
mod section;

use std::io::{Error, ErrorKind};
use std::{env, fs};
use bytemuck::from_bytes;
use crate::scribe::Scribe;
use crate::optional::parse_optional_header;
use crate::coff::coff_file_header;

const IMAGE_DOS_PE_SIGNATURE_OFFSET: usize = 0x3c;

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

    let mut offset = binary[IMAGE_DOS_PE_SIGNATURE_OFFSET] as usize;
    let string = binary.read_string(offset, 4);

    if string != "PE\0\0" {
        return Err(Error::new(ErrorKind::InvalidData, "File is not a valid PE!"));
    }

    offset += 4;

    let header = from_bytes::<coff_file_header>(&binary[offset..offset+20]);

    offset += 20;

    print!("{}\n", header);
    
    let mut has_optional_header = true;

    if header.size_of_optional_header == 0 {
        has_optional_header = false;
    }

    if has_optional_header {
        parse_optional_header(binary, &mut offset)?;
    }

    Ok(())
}