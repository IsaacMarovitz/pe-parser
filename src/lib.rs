//! # pe-parser: Blazing-fast, safe, Portable Executable parsing.
//! 
//! `pe-parser` provides a safe Rust-y way to parse Portable Exectuables quickly.
//! - Everything parsed to native documented structs 
//! - Secondary parsing functions raw data into native Rust types
//! - Every section can be printed with ease
//! 
//! ## Examples
//! ```
//! # use std::{fs, io};
//! use pe_parser::pe::parse_portable_executable;
//! 
//! # fn main() -> io::Result<()> {
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

/// COFF file header definitions and helper functions
pub mod coff;
/// Optional header definitions and helper functions
pub mod optional;
/// Section header definitions and helper functions
pub mod section;
/// Monolith struct containing all the information
/// you will ever need
pub mod pe;