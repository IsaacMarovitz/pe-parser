use std::io::{Error};
use std::{env, fs};
use pe_parser::pe::parse_portable_executable;
use clap::{Arg, command, ArgAction};

fn main() -> Result<(), Error> {
    let matches = command!()
        .arg(Arg::new("file")
            .action(ArgAction::Set)
            .help("The PE binary to parse"))
        .arg(Arg::new("all")
            .short('a')
            .long("all")
            .action(ArgAction::SetTrue)
            .help("Print all sections of PE"))
        .arg(Arg::new("coff")
            .short('c')
            .long("coff")
            .action(ArgAction::SetTrue)
            .help("Print COFF header"))
        .arg(Arg::new("optional")
            .short('o')
            .long("optional")
            .action(ArgAction::SetTrue)
            .help("Print optional section (if present)"))
        .arg(Arg::new("section")
            .short('s')
            .long("section")
            .action(ArgAction::SetTrue)
            .help("Print section table"))
        .get_matches();

    if let Some(file) = matches.get_one::<String>("file") {
        const VERSION: &str = env!("CARGO_PKG_VERSION");
        println!("PE Parser - Version {}", VERSION);
        println!("=========================\n");

        let binary = fs::read(file)
            .expect("Failed to read file");
    
        let pe = parse_portable_executable(binary.as_slice())
            .expect("Failed to parse Portable Executable!");
    
        if matches.get_flag("all") {
            print!("{}", pe);
        } else {
            if matches.get_flag("coff") {
                println!("{}", pe.coff);
            }

            if matches.get_flag("optional") {
                if let Some(optional) = pe.optional_header_32 {
                    println!("{}", optional);
                }

                if let Some(optional) = pe.optional_header_64 {
                    println!("{}", optional);
                }
            }

            if matches.get_flag("section") {
                for section in pe.section_table.iter() {
                    println!("{}", section);
                }
            }
        }
    } else {
        println!("No PE file passed to parse!");
    };

    Ok(())
}