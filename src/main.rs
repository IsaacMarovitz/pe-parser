mod scribe;
mod coff;
mod optional;

use std::io::{Error, ErrorKind};
use std::{env, fs};
use bytemuck::from_bytes;
use num_traits::FromPrimitive;
use crate::scribe::Scribe;
use crate::coff::{coff_file_header, MachineTypes, Characteristics};

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

    let machine_type = MachineTypes::from_u16(header.machine)
        .expect("Failed to get machine type");
    let characteristics = Characteristics::from_bits(header.characterisitcs)
        .expect("Failed to get characterisitcs");
    let mut hasOptionalHeader = true;

    if header.size_of_optional_header == 0 {
        hasOptionalHeader = false;
    }

    println!("COFF Header");
    println!("-----------");
    println!("Machine Type: {:?}", machine_type);
    println!("Number of Sections: {}", header.number_of_sections);
    println!("Size of Optional Header: {}", header.size_of_optional_header);
    println!("Characteristics: {}\n", characteristics);

    if hasOptionalHeader {
        match optional::parse_optional_header(binary, offset) {
            Ok(()) => {},
            Err(err) => {
                return Err(err);
            }
        }
    }

    Ok(())
}