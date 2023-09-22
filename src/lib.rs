//! # pe-parser: Blazing-fast, safe, Portable Executable parsing.
//! 
//! `pe-parser` provides a safe Rust-y way to parse Portable Executables quickly.
//! - Everything parsed to native documented structs 
//! - Secondary parsing functions raw data into native Rust types
//! - Every section can be printed with ease
//! 
//! ## Examples
//! ```
//! # use std::{fs, io};
//! use pe_parser::pe::parse_portable_executable;
//! 
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let path_to_pe = "tests/pe/64_pe/64_pe_checksum_non_zero.dat";
//! // Read the binary from a file
//! let binary = fs::read(path_to_pe)?;
//!  
//! // Parse it!
//! let pe = parse_portable_executable(binary.as_slice())?;
//! // Print all that technical goodness
//! print!("{}", pe);
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use crate::prelude::*;
use core::fmt;

/// COFF file header definitions and helper functions
pub mod coff;
/// Optional header definitions and helper functions
pub mod optional;
/// Section header definitions and helper functions
pub mod section;
/// Monolith struct containing all the information
/// you will ever need
pub mod pe;
mod prelude;

/// Error parsing a PE binary.
#[derive(Debug)]
pub enum Error {
    /// Failed to read data; premature EOF.
    OffsetOutOfRange,
    /// Failed to parse a header for an optional.
    BadOptionalHeader,
    /// Failed to parse a String.
    BadString(alloc::string::FromUtf8Error),
    /// Missing PE header.
    MissingPeHeader,
    /// Missing COFF header.
    MissingCoffHeader,
    /// Missing magic number from header.
    MissingMagicNumber,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OffsetOutOfRange => f.write_str("Offset out of range!"),
            Error::BadOptionalHeader => f.write_str("Failed to parse optional header!"),
            Error::BadString(e) => f.write_fmt(format_args!("Failed to parse string: {}!", e)),
            Error::MissingPeHeader => f.write_str("Missing PE header!"),
            Error::MissingCoffHeader => f.write_str("Missing COFF header!"),
            Error::MissingMagicNumber => f.write_str("Missing magic number!"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
