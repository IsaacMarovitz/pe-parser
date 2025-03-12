use std::path::Path;
use datatest_stable::Result;
use pe_parser::pe::parse_portable_executable;
use std::fs;

fn gauntlet(path: &Path) -> Result<()> {
    let binary = fs::read(path)?;
    let pe = parse_portable_executable(binary.as_slice())?;

    // Binary passed initial parsing, now check if reserved fields are 0

    if let Some(optional) = pe.optional_header_32 {
        assert_eq!(optional.data_directories.architecture.size, 0);
        assert_eq!(optional.data_directories.architecture.virtual_address, 0);
        assert_eq!(optional.data_directories.reserved.size, 0);
        assert_eq!(optional.data_directories.reserved.virtual_address, 0);

        assert_eq!(optional.win32_version_value, 0);
        assert_eq!(optional.loader_flags, 0);
    }

    if let Some(optional) = pe.optional_header_64 {
        assert_eq!(optional.data_directories.architecture.size, 0);
        assert_eq!(optional.data_directories.architecture.virtual_address, 0);
        assert_eq!(optional.data_directories.reserved.size, 0);
        assert_eq!(optional.data_directories.reserved.virtual_address, 0);

        assert_eq!(optional.win32_version_value, 0);
        assert_eq!(optional.loader_flags, 0);
    }

    Ok(())
}

datatest_stable::harness! {
    { test = gauntlet, root = "tests/pe", pattern = r"\.((dat)|(exe)|(dll))$" },
}