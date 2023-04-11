mod scribe;
mod coff;

use std::io::{Error, ErrorKind};
use std::{env, fs};
use bytemuck::from_bytes;
use num_traits::FromPrimitive;
use crate::scribe::Scribe;
use crate::coff::{coff_file_header, MachineTypes};

const IMAGE_DOS_PE_SIGNATURE_OFFSET: usize = 0x3c;

fn main() -> Result<(), Error>{
    let args: Vec<String> = env::args().collect();

    let file_path = &args[1];
    let binary = fs::read(file_path)
        .expect("Failed to read file");

    let mut index = binary[IMAGE_DOS_PE_SIGNATURE_OFFSET] as usize;
    let string = binary.read_string(index, 4);

    if string != "PE\0\0" {
        return Err(Error::new(ErrorKind::InvalidData, "File is not a valid PE!"));
    }

    index += 4;

    let header = from_bytes::<coff_file_header>(&binary[index..index+20]);
    let machine_type = MachineTypes::from_u16(header.machine)
        .expect("Failed to get machine type");
    println!("{:?}", machine_type);

    Ok(())
}