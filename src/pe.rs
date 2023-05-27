use crate::{coff::coff_file_header, optional::{optional_header_32, optional_header_64, Magic, Optional}, section::{section_header, parse_section_table}, Error};
use bytemuck::checked::try_from_bytes;
use num_traits::FromPrimitive;
use core::fmt;
use crate::prelude::*;

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
    let mut offset = read_u16(binary, IMAGE_DOS_PE_SIGNATURE_OFFSET)?.into();

    let slice = match binary.get(offset..offset+4) {
        Some(slice) => slice,
        None => {
            return Err(Error::OffsetOutOfRange);
        }
    };

    let string = match String::from_utf8(slice.to_vec()) {
        Ok(string) => string,
        Err(e) => {
            return Err(Error::BadString(e));
        }
    };

    if string != "PE\0\0" {
        return Err(Error::MissingPeHeader);
    }

    offset += 4;

    let mut pe: PortableExecutable = PortableExecutable { 
        coff: coff_file_header::default(), 
        optional_header_32: None, 
        optional_header_64: None, 
        section_table: Vec::new()
    };

    let slice = match binary.get(offset..offset+20) {
        Some(slice) => slice,
        None => {
            return Err(Error::OffsetOutOfRange);
        }
    };

    pe.coff = match try_from_bytes::<coff_file_header>(slice) {
        Ok(coff) => *coff,
        Err(_) => {
            return Err(Error::MissingCoffHeader);
        }
    };

    offset += 20;

    if pe.coff.size_of_optional_header != 0 {
        let magic = match Magic::from_u16(read_u16(binary, offset)?) {
            Some(magic) => magic,
            None => {
                return Err(Error::MissingMagicNumber);
            }
        };

        match magic {
            Magic::PE32 => {
                pe.optional_header_32 = Some(optional_header_32::parse_optional_header(binary, &mut offset)?);
            }
            Magic::PE64 => {
                pe.optional_header_64 = Some(optional_header_64::parse_optional_header(binary, &mut offset)?);
            }
        }
    }

    pe.section_table = parse_section_table(binary, offset, pe.coff.number_of_sections);

    /*for section in pe.section_table.iter() {
        let name = match section.get_name() {
            Some(name) => name,
            None => {
                return Err(Error::new(ErrorKind::Other, "Failed to get section name"));
            }
        };

        match name.trim_end_matches(char::from(0)) {
            ".edata" => {
                println!(".edata Section");
            }
            ".idata" => {
                println!(".idata Section");
            }
            _ => {}
        }
    }*/

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

fn read_u16(binary: &[u8], offset: usize) -> Result<u16, Error> {
    if let Some(array) = binary.get(offset..offset+2) {
        if let Ok(slice) = array.try_into() {
            Ok(u16::from_le_bytes(slice))
        } else {
            unreachable!()
        }
    } else {
        Err(Error::OffsetOutOfRange)
    }

}