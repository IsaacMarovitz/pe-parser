use bytemuck::{Pod, Zeroable, from_bytes};
use num_derive::FromPrimitive;    
use num_traits::FromPrimitive;
use std::io::{Error, ErrorKind};

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
            println!("Magic: PE32");
        }
        Magic::PE64 => {
            let optional_header = from_bytes::<optional_header_64>(&binary[offset..offset+112]);
            offset += 112;
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