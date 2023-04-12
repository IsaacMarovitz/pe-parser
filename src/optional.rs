use bytemuck::{Pod, Zeroable, from_bytes};
use num_derive::FromPrimitive;    
use num_traits::FromPrimitive;
use std::io::{Error, ErrorKind};
use bitflags::bitflags;
use std::{fmt, str};

use crate::scribe::Scribe;

pub fn parse_optional_header(binary: Vec<u8>, offset: usize) -> Result<(), Error> {
    let mut offset = offset;
    let magic = binary.read_u16(offset);

    let magic = Magic::from_u16(magic)
        .expect("Failed to get magic!");

    println!("Optional Header");
    println!("---------------");

    match magic {
        Magic::PE32 => {
            let optional_header = from_bytes::<optional_header_32>(&binary[offset..offset+96]);
            offset += 96;

            let subsystem = Subsystem::from_u16(optional_header.subsystem)
                .expect("Failed to get subsystem");
            let dllCharacteristics = DLLCharacteristics::from_bits(optional_header.dll_characteristics)
                .expect("Failed to get DLL characteristics");

            println!("Magic: PE32");
            println!("Major Linker Version: {}", optional_header.major_linker_version);
            println!("Minor Linker Version: {}", optional_header.minor_linker_version);
            println!("Size of Code: {}", optional_header.size_of_code);
            println!("Size of Initialized Data: {}", optional_header.size_of_initialized_data);
            println!("Size of Uninitialized Data: {}", optional_header.size_of_uninitialized_data);
            println!("Address of Entry Point: {}", optional_header.address_of_entry_point);
            println!("Base of Code: {}", optional_header.base_of_code);
            println!("Base of Data: {}", optional_header.base_of_data);
            println!("Image Base: {}", optional_header.image_base);
            println!("Section Alignment: {}", optional_header.section_alignment);
            println!("File Alignment: {}", optional_header.file_alignment);
            println!("Major Operating System Version: {}", optional_header.major_operating_system_version);
            println!("Minor Operating System Version: {}", optional_header.minor_operating_system_version);
            println!("Major Image Version: {}", optional_header.major_image_version);
            println!("Minor Image Version: {}", optional_header.minor_image_version);
            println!("Major Subsystem Version: {}", optional_header.major_subsystem_version);
            println!("Minor Subsystem Version: {}", optional_header.minor_subsystem_version);
            println!("Win32 Version Value: {}", optional_header.win32_version_value);
            println!("Size of Image: {}", optional_header.size_of_image);
            println!("Size of Headers: {}", optional_header.size_of_headers);
            println!("CheckSum: {}", optional_header.check_sum);
            println!("Subsystem: {:?}", subsystem);
            println!("DLL Characteristics: {}", dllCharacteristics);
            println!("Size of Stack Reserve: {}", optional_header.size_of_stack_reserve);
            println!("Size of Stack Commit: {}", optional_header.size_of_stack_commit);
            println!("Size of Heap Reserve: {}", optional_header.size_of_heap_reserve);
            println!("Size of Heap Commit: {}", optional_header.size_of_heap_commit);
            println!("Loader Flags: {}", optional_header.loader_flags);
            println!("Number of RVA and Sizes: {}", optional_header.number_of_rva_and_sizes);
        }
        Magic::PE64 => {
            let optional_header = from_bytes::<optional_header_64>(&binary[offset..offset+112]);
            offset += 112;

            let subsystem = Subsystem::from_u16(optional_header.subsystem)
                .expect("Failed to get subsystem");
            let dllCharacteristics = DLLCharacteristics::from_bits(optional_header.dll_characteristics)
                .expect("Failed to get DLL characteristics");

            println!("Magic: PE32+");
            println!("Major Linker Version: {}", optional_header.major_linker_version);
            println!("Minor Linker Version: {}", optional_header.minor_linker_version);
            println!("Size of Code: {}", optional_header.size_of_code);
            println!("Size of Initialized Data: {}", optional_header.size_of_initialized_data);
            println!("Size of Uninitialized Data: {}", optional_header.size_of_uninitialized_data);
            println!("Address of Entry Point: {}", optional_header.address_of_entry_point);
            println!("Base of Code: {}", optional_header.base_of_code);
            println!("Image Base: {}", optional_header.image_base);
            println!("Section Alignment: {}", optional_header.section_alignment);
            println!("File Alignment: {}", optional_header.file_alignment);
            println!("Major Operating System Version: {}", optional_header.major_operating_system_version);
            println!("Minor Operating System Version: {}", optional_header.minor_operating_system_version);
            println!("Major Image Version: {}", optional_header.major_image_version);
            println!("Minor Image Version: {}", optional_header.minor_image_version);
            println!("Major Subsystem Version: {}", optional_header.major_subsystem_version);
            println!("Minor Subsystem Version: {}", optional_header.minor_subsystem_version);
            println!("Win32 Version Value: {}", optional_header.win32_version_value);
            println!("Size of Image: {}", optional_header.size_of_image);
            println!("Size of Headers: {}", optional_header.size_of_headers);
            println!("CheckSum: {}", optional_header.check_sum);
            println!("Subsystem: {:?}", subsystem);
            println!("DLL Characteristics: {}", dllCharacteristics);
            println!("Size of Stack Reserve: {}", optional_header.size_of_stack_reserve);
            println!("Size of Stack Commit: {}", optional_header.size_of_stack_commit);
            println!("Size of Heap Reserve: {}", optional_header.size_of_heap_reserve);
            println!("Size of Heap Commit: {}", optional_header.size_of_heap_commit);
            println!("Loader Flags: {}", optional_header.loader_flags);
            println!("Number of RVA and Sizes: {}", optional_header.number_of_rva_and_sizes);
        }
    }
    println!();
    Ok(())
}

#[derive(FromPrimitive, Debug)]
#[repr(u16)]
pub enum Magic {
    PE32 = 0x10b,
    PE64 = 0x20b
}

/// PE32 Optional Header (Image Only)
#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct optional_header_32 {
    /// The unsigned integer that identifies the state of the image file.
    /// The most common number is 0x10B, which identifies it as a normal executable file.
    /// 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable.
    pub magic: u16,
    /// The linker major version number.
    pub major_linker_version: u8,
    /// The linker minor version number.
    pub minor_linker_version: u8,
    /// The size of the code (text) section, or the sum of all code sections if there are multiple sections.
    pub size_of_code: u32,
    /// The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
    pub size_of_initialized_data: u32,
    /// The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
    pub size_of_uninitialized_data: u32,
    /// The address of the entry point relative to the image base when the executable file is loaded into memory.
    /// For program images, this is the starting address.
    /// For device drivers, this is the address of the initialization function.
    /// An entry point is optional for DLLs. When no entry point is present, this field must be zero.
    pub address_of_entry_point: u32,
    /// The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
    pub base_of_code: u32,
    /// (PE32 Only) The address that is relative to the image base of the beginning-of-data section when it is loaded into memory.
    pub base_of_data: u32,
    /// The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K.
    /// The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000.
    /// The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
    pub image_base: u32,
    /// The alignment (in bytes) of sections when they are loaded into memory.
    /// It must be greater than or equal to `file_alignment`. The default is the page size for the architecture.
    pub section_alignment: u32,
    /// The alignment factor (in bytes) that is used to align the raw data of sections in the image file.
    /// The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512.
    /// If the `section_alignment` is less than the architecture's page size, then `file_alignment` must match `section_alignment`.
    pub file_alignment: u32,
    /// The major version number of the required operating system.
    pub major_operating_system_version: u16,
    /// The minor version number of the required operating system.
    pub minor_operating_system_version: u16,
    /// The major version number of the image.
    pub major_image_version: u16,
    /// The minor version number of the image.
    pub minor_image_version: u16,
    /// The major version number of the subsystem.
    pub major_subsystem_version: u16,
    /// The minor version number of the subsystem.
    pub minor_subsystem_version: u16,
    /// Reserved, must be zero.
    pub win32_version_value: u32,
    /// The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of `section_alignment`.
    pub size_of_image: u32,
    /// The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of `file_alignment`.
    pub size_of_headers: u32,
    /// The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. 
    /// The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
    pub check_sum: u32,
    /// The subsystem that is required to run this image.
    pub subsystem: u16,
    pub dll_characteristics: u16,
    /// The size of the stack to reserve. Only `size_of_stack_commit` is committed; the rest is made available one page at a time until the reserve size is reached.
    pub size_of_stack_reserve: u32,
    /// The size of the stack to commit.
    pub size_of_stack_commit: u32,
    /// The size of the local heap space to reserve. Only `size_of_heap_commit` is committed; the rest is made available one page at a time until the reserve size is reached.
    pub size_of_heap_reserve: u32,
    /// The size of the local heap space to commit.
    pub size_of_heap_commit: u32,
    /// Reserved, must be zero.
    pub loader_flags: u32,
    /// The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
    pub number_of_rva_and_sizes: u32
}

/// PE32+ Optional Header (Image Only)
#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct optional_header_64 {
    /// The unsigned integer that identifies the state of the image file.
    /// The most common number is 0x10B, which identifies it as a normal executable file.
    /// 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable.
    pub magic: u16,
    /// The linker major version number.
    pub major_linker_version: u8,
    /// The linker minor version number.
    pub minor_linker_version: u8,
    /// The size of the code (text) section, or the sum of all code sections if there are multiple sections.
    pub size_of_code: u32,
    /// The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
    pub size_of_initialized_data: u32,
    /// The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
    pub size_of_uninitialized_data: u32,
    /// The address of the entry point relative to the image base when the executable file is loaded into memory.
    /// For program images, this is the starting address.
    /// For device drivers, this is the address of the initialization function.
    /// An entry point is optional for DLLs. When no entry point is present, this field must be zero.
    pub address_of_entry_point: u32,
    /// The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
    pub base_of_code: u32,
    /// The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K.
    /// The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000.
    /// The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
    pub image_base: u64,
    /// The alignment (in bytes) of sections when they are loaded into memory.
    /// It must be greater than or equal to `file_alignment`. The default is the page size for the architecture.
    pub section_alignment: u32,
    /// The alignment factor (in bytes) that is used to align the raw data of sections in the image file.
    /// The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512.
    /// If the `section_alignment` is less than the architecture's page size, then `file_alignment` must match `section_alignment`.
    pub file_alignment: u32,
    /// The major version number of the required operating system.
    pub major_operating_system_version: u16,
    /// The minor version number of the required operating system.
    pub minor_operating_system_version: u16,
    /// The major version number of the image.
    pub major_image_version: u16,
    /// The minor version number of the image.
    pub minor_image_version: u16,
    /// The major version number of the subsystem.
    pub major_subsystem_version: u16,
    /// The minor version number of the subsystem.
    pub minor_subsystem_version: u16,
    /// Reserved, must be zero.
    pub win32_version_value: u32,
    /// The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of `section_alignment`.
    pub size_of_image: u32,
    /// The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of `file_alignment`.
    pub size_of_headers: u32,
    /// The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. 
    /// The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
    pub check_sum: u32,
    /// The subsystem that is required to run this image.
    pub subsystem: u16,
    pub dll_characteristics: u16,
    /// The size of the stack to reserve. Only `size_of_stack_commit` is committed; the rest is made available one page at a time until the reserve size is reached.
    pub size_of_stack_reserve: u64,
    /// The size of the stack to commit.
    pub size_of_stack_commit: u64,
    /// The size of the local heap space to reserve. Only `size_of_heap_commit` is committed; the rest is made available one page at a time until the reserve size is reached.
    pub size_of_heap_reserve: u64,
    /// The size of the local heap space to commit.
    pub size_of_heap_commit: u64,
    /// Reserved, must be zero.
    pub loader_flags: u32,
    /// The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
    pub number_of_rva_and_sizes: u32
}

/// The following values defined for the Subsystem field of the optional header determine which Windows subsystem (if any) is required to run the image.
#[derive(FromPrimitive, Debug)]
#[repr(u16)]
pub enum Subsystem {
    /// An unknown subsystem
    Unkown = 0,
    /// Device drivers and native Windows processes
    Native = 1,
    /// The Windows graphical user interface (GUI) subsystem
    WindowsGUI = 2,
    /// The Windows character subsystem
    WindowsCUI = 3,
    /// The OS/2 character subsystem
    OS2CUI = 5,
    /// The Posix character subsystem
    PosixCUI = 7,
    /// Native Win9x driver
    NativeWindows = 8,
    /// Windows CE
    WindowsCEGUI = 9,
    /// An Extensible Firmware Interface (EFI) application
    EFIApplication = 10,
    /// An EFI driver with boot services
    EFIBootServiceDriver = 11,
    /// An EFI driver with run-time services
    EFIRuntimeDriver = 12,
    /// An EFI ROM image
    EFIROM = 13,
    /// XBOX
    XBOX = 14,
    /// Windows boot application
    WindowsBootApplication = 16
}

bitflags! {
    pub struct DLLCharacteristics: u16 {
        /// Reserved, must be zero.
        const reserved1 = 0x0001;
        /// Reserved, must be zero.
        const reserved2 = 0x0002;
        /// Reserved, must be zero.
        const reserved4 = 0x0004;
        /// Reserved, must be zero.
        const reserved8 = 0x0008;
        /// Image can handle a high entropy 64-bit virtual address space.
        const highEntropyVA = 0x0020;
        /// DLL can be relocated at load time.
        const dynamicBase = 0x0040;
        /// Code Integrity checks are enforced.
        const forceIntegrity = 0x0080;
        /// Image is NX compatible.
        const nxCompat = 0x0100;
        /// Isolation aware, but do not isolate the image.
        const noIsolation = 0x0200;
        /// Does not use structured exception (SE) handling. 
        /// No SE handler may be called in this image.
        const noSEH = 0x0400;
        /// Do not bind the image.
        const noBind = 0x0800;
        /// Image must execute in an AppContainer.
        const appContainer = 0x1000;
        /// A WDM driver.
        const wdmDriver = 0x2000;
        /// Image supports Control Flow Guard.
        const guardCF = 0x4000;
        /// Terminal Server aware.
        const terminalServerAware = 0x8000;
    }
}

// Allow DLL Characteristics flags to be easily printed
impl fmt::Debug for DLLCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for DLLCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl str::FromStr for DLLCharacteristics {
    type Err = bitflags::parser::ParseError;

    fn from_str(flags: &str) -> Result<Self, Self::Err> {
        Ok(Self(flags.parse()?))
    }
}