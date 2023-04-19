use crate::{coff_file_header, parse_section_table, scribe::Scribe, optional::{optional_header_32, optional_header_64, Magic, Optional}, section::section_header};
use std::io::{Error, ErrorKind};
use bytemuck::from_bytes;
use num_traits::FromPrimitive;
use std::{fmt};

const IMAGE_DOS_PE_SIGNATURE_OFFSET: usize = 0x3c;

pub struct PortableExecutable {
    pub coff: coff_file_header,
    pub optional_header_32: Option<optional_header_32>,
    pub optional_header_64: Option<optional_header_64>,
    pub section_table: Vec<section_header>,
}

pub fn parse_portable_executable(binary: &[u8]) -> Result<PortableExecutable, Error> {
    let mut offset = binary.read_u16(IMAGE_DOS_PE_SIGNATURE_OFFSET) as usize;
    let string = binary.read_string(offset, 4);
    let mut pe: PortableExecutable = PortableExecutable { 
        coff: coff_file_header::default(), 
        optional_header_32: None, 
        optional_header_64: None, 
        section_table: Vec::new()
    };

    if string != "PE\0\0" {
        return Err(Error::new(ErrorKind::InvalidData, "File is not a valid PE!"));
    }

    offset += 4;

    pe.coff = *from_bytes::<coff_file_header>(&binary[offset..offset+20]);

    offset += 20;

    if pe.coff.size_of_optional_header != 0 {
        let magic = Magic::from_u16(binary.read_u16(offset))
            .expect("Failed to get magic!");

        match magic {
            Magic::PE32 => {
                pe.optional_header_32 = optional_header_32::parse_optional_header(binary, &mut offset).ok();
            }
            Magic::PE64 => {
                pe.optional_header_64 = optional_header_64::parse_optional_header(binary, &mut offset).ok();
            }
        }
    }

    pe.section_table = parse_section_table(binary, offset, pe.coff.number_of_sections);

    Ok(pe)
}

impl fmt::Display for PortableExecutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{}", self.coff)?;

        match self.optional_header_32 {
            None => (),
            Some(header) => {
                writeln!(f, "{}", header)?;
            }
        }

        match self.optional_header_64 {
            None => (),
            Some(header) => {
                writeln!(f, "{}", header)?;
            }
        }

        for section in self.section_table.iter() {
            writeln!(f, "{}", section)?;
        }

        Ok(())
    }
}