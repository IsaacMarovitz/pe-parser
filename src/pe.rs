use crate::{coff::coff_file_header, optional::{optional_header_32, optional_header_64, Magic, Optional}, section::{section_header, parse_section_table}};
use std::io::{Error, ErrorKind};
use bytemuck::checked::try_from_bytes;
use num_traits::FromPrimitive;
use std::fmt;

const IMAGE_DOS_PE_SIGNATURE_OFFSET: usize = 0x3c;

/// Representation of the sections of a Portable Executable
pub struct PortableExecutable {
    /// COFF File Header (Object and Image)
    pub coff: coff_file_header,
    /// PE32 Optional Header (Image Only)
    pub optional_header_32: Option<optional_header_32>,
    /// PE32+ Optional Header (Image Only)
    pub optional_header_64: Option<optional_header_64>,
    /// Table containing a list of section headers
    pub section_table: Vec<section_header>,
}

/// Parse a Portable Executable from a given byte array
pub fn parse_portable_executable(binary: &[u8]) -> Result<PortableExecutable, Error> {
    let mut offset = read_u16(binary, IMAGE_DOS_PE_SIGNATURE_OFFSET).into();

    let string = String::from_utf8(binary[offset..offset+4].to_vec())
        .expect("Failed to get PE Signature");

    if string != "PE\0\0" {
        return Err(Error::new(ErrorKind::InvalidData, "File is not a valid PE!"));
    }

    offset += 4;

    let mut pe: PortableExecutable = PortableExecutable { 
        coff: coff_file_header::default(), 
        optional_header_32: None, 
        optional_header_64: None, 
        section_table: Vec::new()
    };

    pe.coff = *try_from_bytes::<coff_file_header>(&binary[offset..offset+20])
        .expect("Failed to get COFF!");

    offset += 20;

    if pe.coff.size_of_optional_header != 0 {
        let magic = Magic::from_u16(read_u16(binary, offset))
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

    for section in pe.section_table.iter() {
        let name = section.get_name()
            .expect("Failed to get name");

        match name.trim_end_matches(char::from(0)) {
            ".edata" => {
                println!(".edata Section");
            }
            ".idata" => {
                println!(".idata Section");
            }
            _ => {}
        }
    }

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

fn read_u16(binary: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(binary[offset..offset+2]
        .try_into()
        .expect("Failed to get u16 value!"))
}