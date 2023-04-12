use bytemuck::{Pod, Zeroable, from_bytes};
use num_derive::FromPrimitive;    
use num_traits::FromPrimitive;
use std::{io::Error, ops::AddAssign};
use bitflags::bitflags;
use std::{fmt, str};

use crate::scribe::Scribe;

pub fn parse_optional_header(binary: &[u8], offset: &mut usize) -> Result<(), Error> {
    let magic = Magic::from_u16(binary.read_u16(*offset))
        .expect("Failed to get magic!");

    match magic {
        Magic::PE32 => {
            let optional_header = from_bytes::<optional_header_32>(&binary[*offset..*offset+96+128]);
            offset.add_assign(96 + 128);
            print!("{}\n", optional_header);
        }
        Magic::PE64 => {
            let optional_header = from_bytes::<optional_header_64>(&binary[*offset..*offset+112+128]);
            offset.add_assign(112 + 128);
            print!("{}\n", optional_header);
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

#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct data_directories {
    /// The export table (.edata) address and size. (Image Only)
    pub export_table: data_directory,
    /// The import table (.idata) address and size.
    pub import_table: data_directory,
    /// The resource table (.rsrc) address and size.
    pub resource_table: data_directory,
    /// The exception table (.pdata) address and size.
    pub exception_table: data_directory,
    /// The attribute certificate table address and size. (Image Only)
    pub certificate_table: data_directory,
    /// The base relocation table (.reloc) address and size. (Image Only)
    pub base_relocation_table: data_directory,
    /// The debug data (.debug) starting address and size.
    pub debug: data_directory,
    /// Reserved, must be 0.
    pub architecture: data_directory,
    /// The RVA of the value to be stored in the global pointer register.
    /// The size member of this structure must be set to zero.
    pub global_ptr: data_directory,
    /// The thread local storage (TLS) table (.tls) address and size.
    pub tls_table: data_directory,
    /// The load configuration table address and size. (Image Only)
    pub load_config_table: data_directory,
    /// The bound import table address and size.
    pub bound_import: data_directory,
    /// The import address table address and size.
    pub import_address_table: data_directory,
    /// The delay import descriptor address and size. (Image Only)
    pub delay_import_descriptor: data_directory,
    /// The CLR runtime header (.cormeta) address and size. (Object Only
    pub clr_runtime_header: data_directory,
    /// Reserved, must be zero.
    pub reserved: data_directory
}

impl fmt::Display for data_directories {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Data Directories")?;
        writeln!(f, "----------------")?;
        writeln!(f, "Export Table:            {:#08x} ({})", self.export_table.virtual_address, self.export_table.size)?;
        writeln!(f, "Import Table:            {:#08x} ({})", self.import_table.virtual_address, self.import_table.size)?;
        writeln!(f, "Resource Table:          {:#08x} ({})", self.resource_table.virtual_address, self.resource_table.size)?;
        writeln!(f, "Exception Table:         {:#08x} ({})", self.exception_table.virtual_address, self.exception_table.size)?;
        writeln!(f, "Certificiate Table:      {:#08x} ({})", self.certificate_table.virtual_address, self.certificate_table.size)?;
        writeln!(f, "Base Relocation Table:   {:#08x} ({})", self.base_relocation_table.virtual_address, self.base_relocation_table.size)?;
        writeln!(f, "Debug:                   {:#08x} ({})", self.debug.virtual_address, self.debug.size)?;
        writeln!(f, "Architecture:            {:#08x} ({})", self.architecture.virtual_address, self.architecture.size)?;
        writeln!(f, "Global Pointer:          {:#08x} ({})", self.global_ptr.virtual_address, self.global_ptr.size)?;
        writeln!(f, "TLS Table:               {:#08x} ({})", self.tls_table.virtual_address, self.tls_table.size)?;
        writeln!(f, "Load Config Table:       {:#08x} ({})", self.load_config_table.virtual_address, self.load_config_table.size)?;
        writeln!(f, "Bound Import:            {:#08x} ({})", self.bound_import.virtual_address, self.bound_import.size)?;
        writeln!(f, "Import Address Table:    {:#08x} ({})", self.import_address_table.virtual_address, self.import_address_table.size)?;
        writeln!(f, "Delay Import Descriptor: {:#08x} ({})", self.delay_import_descriptor.virtual_address, self.delay_import_descriptor.size)?;
        writeln!(f, "CLR Runtime Header:      {:#08x} ({})", self.clr_runtime_header.virtual_address, self.clr_runtime_header.size)?;
        writeln!(f, "Reserved:                {:#08x} ({})", self.reserved.virtual_address, self.reserved.size)?;

        Ok(())
    }
}

/// Each data directory gives the address and size of a table or string that Windows uses.
/// These data directory entries are all loaded into memory so that the system can use them at run time.
/// A data directory is an 8-byte field that has the following declaration:
#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct data_directory {
    pub virtual_address: u32,
    pub size: u32
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
    pub number_of_rva_and_sizes: u32,
    pub data_directories: data_directories
}

impl fmt::Display for optional_header_32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subsystem = Subsystem::from_u16(self.subsystem)
            .expect("Failed to get subsystem");
        let dll_characteristics = DLLCharacteristics::from_bits(self.dll_characteristics)
            .expect("Failed to get DLL characteristics");

        writeln!(f, "Optional Header")?;
        writeln!(f, "---------------")?;
        writeln!(f, "Magic: PE32")?;
        writeln!(f, "Linker Version: {}.{}", self.major_linker_version, self.minor_linker_version)?;
        writeln!(f, "Size of Code: {}", self.size_of_code)?;
        writeln!(f, "Size of Initialized Data: {}", self.size_of_initialized_data)?;
        writeln!(f, "Size of Uninitialized Data: {}", self.size_of_uninitialized_data)?;
        writeln!(f, "Address of Entry Point: {:#08x}", self.address_of_entry_point)?;
        writeln!(f, "Base of Code: {:#08x}", self.base_of_code)?;
        writeln!(f, "Base of Data: {:#08x}", self.base_of_data)?;
        writeln!(f, "Image Base: {:#08x}", self.image_base)?;
        writeln!(f, "Section Alignment: {}", self.section_alignment)?;
        writeln!(f, "File Alignment: {}", self.file_alignment)?;
        writeln!(f, "Operating System Version: {}.{}", self.major_operating_system_version, self.minor_operating_system_version)?;
        writeln!(f, "Image Version: {}.{}", self.major_image_version, self.minor_image_version)?;
        writeln!(f, "Subsystem Version: {}.{}", self.major_subsystem_version, self.minor_linker_version)?;
        writeln!(f, "Win32 Version Value: {}", self.win32_version_value)?;
        writeln!(f, "Size of Image: {}", self.size_of_image)?;
        writeln!(f, "Size of Headers: {}", self.size_of_headers)?;
        writeln!(f, "CheckSum: {}", self.check_sum)?;
        writeln!(f, "Subsystem: {:?}", subsystem)?;
        writeln!(f, "DLL Characteristics: {}", dll_characteristics)?;
        writeln!(f, "Size of Stack Reserve: {}", self.size_of_stack_reserve)?;
        writeln!(f, "Size of Stack Commit: {}", self.size_of_stack_commit)?;
        writeln!(f, "Size of Heap Reserve: {}", self.size_of_heap_reserve)?;
        writeln!(f, "Size of Heap Commit: {}", self.size_of_heap_commit)?;
        writeln!(f, "Loader Flags: {}", self.loader_flags)?;
        writeln!(f, "Number of RVA and Sizes: {}", self.number_of_rva_and_sizes)?;
        write!(f, "\n{}", self.data_directories)?;

        Ok(())
    }
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
    pub number_of_rva_and_sizes: u32,
    pub data_directories: data_directories
}

impl fmt::Display for optional_header_64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subsystem = Subsystem::from_u16(self.subsystem)
            .expect("Failed to get subsystem");
        let dll_characteristics = DLLCharacteristics::from_bits(self.dll_characteristics)
            .expect("Failed to get DLL characteristics");

        writeln!(f, "Optional Header")?;
        writeln!(f, "---------------")?;
        writeln!(f, "Magic: PE32+")?;
        writeln!(f, "Linker Version: {}.{}", self.major_linker_version, self.minor_linker_version)?;
        writeln!(f, "Size of Code: {}", self.size_of_code)?;
        writeln!(f, "Size of Initialized Data: {}", self.size_of_initialized_data)?;
        writeln!(f, "Size of Uninitialized Data: {}", self.size_of_uninitialized_data)?;
        writeln!(f, "Address of Entry Point: {:#08x}", self.address_of_entry_point)?;
        writeln!(f, "Base of Code: {:#08x}", self.base_of_code)?;
        writeln!(f, "Image Base: {:#08x}", self.image_base)?;
        writeln!(f, "Section Alignment: {}", self.section_alignment)?;
        writeln!(f, "File Alignment: {}", self.file_alignment)?;
        writeln!(f, "Operating System Version: {}.{}", self.major_operating_system_version, self.minor_operating_system_version)?;
        writeln!(f, "Image Version: {}.{}", self.major_image_version, self.minor_image_version)?;
        writeln!(f, "Subsystem Version: {}.{}", self.major_subsystem_version, self.minor_linker_version)?;
        writeln!(f, "Win32 Version Value: {}", self.win32_version_value)?;
        writeln!(f, "Size of Image: {}", self.size_of_image)?;
        writeln!(f, "Size of Headers: {}", self.size_of_headers)?;
        writeln!(f, "CheckSum: {}", self.check_sum)?;
        writeln!(f, "Subsystem: {:?}", subsystem)?;
        writeln!(f, "DLL Characteristics: {}", dll_characteristics)?;
        writeln!(f, "Size of Stack Reserve: {}", self.size_of_stack_reserve)?;
        writeln!(f, "Size of Stack Commit: {}", self.size_of_stack_commit)?;
        writeln!(f, "Size of Heap Reserve: {}", self.size_of_heap_reserve)?;
        writeln!(f, "Size of Heap Commit: {}", self.size_of_heap_commit)?;
        writeln!(f, "Loader Flags: {}", self.loader_flags)?;
        writeln!(f, "Number of RVA and Sizes: {}", self.number_of_rva_and_sizes)?;
        write!(f, "\n{}", self.data_directories)?;

        Ok(())
    }
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