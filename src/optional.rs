use num_derive::FromPrimitive;    
use num_traits::FromPrimitive;
use std::io::{Error, ErrorKind};

use crate::scribe::Scribe;

pub fn parse_optional_header(binary: Vec<u8>, offset: usize) -> Result<(), Error> {
    let mut offset = offset;
    let magic = binary.read_u16(offset);
    offset += 2;

    let magic = Magic::from_u16(magic)
        .expect("Failed to get magic!");

    println!("Optional Header");
    println!("---------------");

    match magic {
        Magic::PE32 => {
            println!("Magic: PE32");
        }
        Magic::PE64 => {
            println!("Magic: PE32+");
        }
    }

    Ok(())
}

#[derive(FromPrimitive, Debug)]
#[repr(u16)]
pub enum Magic {
    PE32 = 0x10b,
    PE64 = 0x20b
}