#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate pe_parser;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pe_parser::pe::parse_portable_executable(data);
});
