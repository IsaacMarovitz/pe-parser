use bytemuck::{Pod, Zeroable, checked::{try_from_bytes}};
use num_derive::FromPrimitive;    
use num_traits::FromPrimitive;
use bitflags::bitflags;
use core::{fmt, str};
use crate::{prelude::*, Error};

/// Magic values that determine if an Optional Header is 
/// PE32 (32-bit) or PE32+ (64-bit)
#[derive(FromPrimitive, Debug)]
#[repr(u16)]
pub enum Magic {
    /// Magic value for 32-bit PEs
    PE32 = 0x10b,
    /// Magic value for 64-bit PEs
    PE64 = 0x20b
}

/// Struct containing basic information (address and size) of each table. 
#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct DataDirectories {
    /// The export table (.edata) address and size. (Image Only)
    pub export_table: DataDirectory,
    /// The import table (.idata) address and size.
    pub import_table: DataDirectory,
    /// The resource table (.rsrc) address and size.
    pub resource_table: DataDirectory,
    /// The exception table (.pdata) address and size.
    pub exception_table: DataDirectory,
    /// The attribute certificate table address and size. (Image Only)
    pub certificate_table: DataDirectory,
    /// The base relocation table (.reloc) address and size. (Image Only)
    pub base_relocation_table: DataDirectory,
    /// The debug data (.debug) starting address and size.
    pub debug: DataDirectory,
    /// Reserved, must be 0.
    pub architecture: DataDirectory,
    /// The RVA of the value to be stored in the global pointer register.
    /// The size member of this structure must be set to zero.
    pub global_ptr: DataDirectory,
    /// The thread local storage (TLS) table (.tls) address and size.
    pub tls_table: DataDirectory,
    /// The load configuration table address and size. (Image Only)
    pub load_config_table: DataDirectory,
    /// The bound import table address and size.
    pub bound_import: DataDirectory,
    /// The import address table address and size.
    pub import_address_table: DataDirectory,
    /// The delay import descriptor address and size. (Image Only)
    pub delay_import_descriptor: DataDirectory,
    /// The CLR runtime header (.cormeta) address and size. (Object Only
    pub clr_runtime_header: DataDirectory,
    /// Reserved, must be zero.
    pub reserved: DataDirectory
}

impl fmt::Display for DataDirectories {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Data Directories")?;
        writeln!(f, "----------------")?;
        writeln!(f, "Export Table:            {:#010x} ({})", self.export_table.virtual_address, self.export_table.size)?;
        writeln!(f, "Import Table:            {:#010x} ({})", self.import_table.virtual_address, self.import_table.size)?;
        writeln!(f, "Resource Table:          {:#010x} ({})", self.resource_table.virtual_address, self.resource_table.size)?;
        writeln!(f, "Exception Table:         {:#010x} ({})", self.exception_table.virtual_address, self.exception_table.size)?;
        writeln!(f, "Certificiate Table:      {:#010x} ({})", self.certificate_table.virtual_address, self.certificate_table.size)?;
        writeln!(f, "Base Relocation Table:   {:#010x} ({})", self.base_relocation_table.virtual_address, self.base_relocation_table.size)?;
        writeln!(f, "Debug:                   {:#010x} ({})", self.debug.virtual_address, self.debug.size)?;
        writeln!(f, "Architecture:            {:#010x} ({})", self.architecture.virtual_address, self.architecture.size)?;
        writeln!(f, "Global Pointer:          {:#010x} ({})", self.global_ptr.virtual_address, self.global_ptr.size)?;
        writeln!(f, "TLS Table:               {:#010x} ({})", self.tls_table.virtual_address, self.tls_table.size)?;
        writeln!(f, "Load Config Table:       {:#010x} ({})", self.load_config_table.virtual_address, self.load_config_table.size)?;
        writeln!(f, "Bound Import:            {:#010x} ({})", self.bound_import.virtual_address, self.bound_import.size)?;
        writeln!(f, "Import Address Table:    {:#010x} ({})", self.import_address_table.virtual_address, self.import_address_table.size)?;
        writeln!(f, "Delay Import Descriptor: {:#010x} ({})", self.delay_import_descriptor.virtual_address, self.delay_import_descriptor.size)?;
        writeln!(f, "CLR Runtime Header:      {:#010x} ({})", self.clr_runtime_header.virtual_address, self.clr_runtime_header.size)?;
        writeln!(f, "Reserved:                {:#010x} ({})", self.reserved.virtual_address, self.reserved.size)?;

        Ok(())
    }
}

/// Each data directory gives the address and size of a table or string that Windows uses.
/// These data directory entries are all loaded into memory so that the system can use them at run time.
/// A data directory is an 8-byte field that has the following declaration:
#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct DataDirectory {
    /// RVA of the table. The RVA is the address of the table relative to the base address of the image when the table is loaded.
    pub virtual_address: u32,
    /// Size of the table in bytes.
    pub size: u32
}

/// PE32 Optional Header (Image Only)
#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct OptionalHeader32 {
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
    /// Bitflag characteristics that describe how a DLL should be loaded.
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
    /// Struct containing basic information (address and size) of each table. 
    pub data_directories: DataDirectories
}

impl fmt::Display for OptionalHeader32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subsystem = self.get_subsystem()
            .expect("Failed to get subsystem");
        let dll_characteristics = self.get_dll_characteristics()
            .expect("Failed to get DLL characteristics");

        writeln!(f, "Optional Header")?;
        writeln!(f, "---------------")?;
        writeln!(f, "Magic:                      PE32")?;
        writeln!(f, "Linker Version:             {}.{}", self.major_linker_version, self.minor_linker_version)?;
        writeln!(f, "Size of Code:               {}", self.size_of_code)?;
        writeln!(f, "Size of Initialized Data:   {}", self.size_of_initialized_data)?;
        writeln!(f, "Size of Uninitialized Data: {}", self.size_of_uninitialized_data)?;
        writeln!(f, "Address of Entry Point:     {:#010x}", self.address_of_entry_point)?;
        writeln!(f, "Base of Code:               {:#010x}", self.base_of_code)?;
        writeln!(f, "Base of Data:               {:#010x}", self.base_of_data)?;
        writeln!(f, "Image Base:                 {:#010x}", self.image_base)?;
        writeln!(f, "Section Alignment:          {}", self.section_alignment)?;
        writeln!(f, "File Alignment:             {}", self.file_alignment)?;
        writeln!(f, "Operating System Version:   {}.{}", self.major_operating_system_version, self.minor_operating_system_version)?;
        writeln!(f, "Image Version:              {}.{}", self.major_image_version, self.minor_image_version)?;
        writeln!(f, "Subsystem Version:          {}.{}", self.major_subsystem_version, self.minor_linker_version)?;
        writeln!(f, "Win32 Version Value:        {}", self.win32_version_value)?;
        writeln!(f, "Size of Image:              {}", self.size_of_image)?;
        writeln!(f, "Size of Headers:            {}", self.size_of_headers)?;
        writeln!(f, "CheckSum:                   {}", self.check_sum)?;
        writeln!(f, "Subsystem:                  {:?}", subsystem)?;
        writeln!(f, "DLL Characteristics:        {}", dll_characteristics)?;
        writeln!(f, "Size of Stack Reserve:      {}", self.size_of_stack_reserve)?;
        writeln!(f, "Size of Stack Commit:       {}", self.size_of_stack_commit)?;
        writeln!(f, "Size of Heap Reserve:       {}", self.size_of_heap_reserve)?;
        writeln!(f, "Size of Heap Commit:        {}", self.size_of_heap_commit)?;
        writeln!(f, "Loader Flags:               {}", self.loader_flags)?;
        writeln!(f, "Number of RVA and Sizes:    {}", self.number_of_rva_and_sizes)?;
        write!(f, "\n{}", self.data_directories)?;

        Ok(())
    }
}

/// PE32+ Optional Header (Image Only)
#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct OptionalHeader64 {
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
    /// Bitflag characteristics that describe how a DLL should be loaded.
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
    /// Struct containing basic information (address and size) of each table. 
    pub data_directories: DataDirectories
}

impl fmt::Display for OptionalHeader64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let subsystem = self.get_subsystem()
            .expect("Failed to get subsystem");
        let dll_characteristics = self.get_dll_characteristics()
            .expect("Failed to get DLL characteristics");

        writeln!(f, "Optional Header")?;
        writeln!(f, "---------------")?;
        writeln!(f, "Magic:                      PE32+")?;
        writeln!(f, "Linker Version:             {}.{}", self.major_linker_version, self.minor_linker_version)?;
        writeln!(f, "Size of Code:               {}", self.size_of_code)?;
        writeln!(f, "Size of Initialized Data:   {}", self.size_of_initialized_data)?;
        writeln!(f, "Size of Uninitialized Data: {}", self.size_of_uninitialized_data)?;
        writeln!(f, "Address of Entry Point:     {:#010x}", self.address_of_entry_point)?;
        writeln!(f, "Base of Code:               {:#010x}", self.base_of_code)?;
        writeln!(f, "Image Base:                 {:#010x}", self.image_base)?;
        writeln!(f, "Section Alignment:          {}", self.section_alignment)?;
        writeln!(f, "File Alignment:             {}", self.file_alignment)?;
        writeln!(f, "Operating System Version:   {}.{}", self.major_operating_system_version, self.minor_operating_system_version)?;
        writeln!(f, "Image Version:              {}.{}", self.major_image_version, self.minor_image_version)?;
        writeln!(f, "Subsystem Version:          {}.{}", self.major_subsystem_version, self.minor_linker_version)?;
        writeln!(f, "Win32 Version Value:        {}", self.win32_version_value)?;
        writeln!(f, "Size of Image:              {}", self.size_of_image)?;
        writeln!(f, "Size of Headers:            {}", self.size_of_headers)?;
        writeln!(f, "CheckSum:                   {}", self.check_sum)?;
        writeln!(f, "Subsystem:                  {:?}", subsystem)?;
        writeln!(f, "DLL Characteristics:        {}", dll_characteristics)?;
        writeln!(f, "Size of Stack Reserve:      {}", self.size_of_stack_reserve)?;
        writeln!(f, "Size of Stack Commit:       {}", self.size_of_stack_commit)?;
        writeln!(f, "Size of Heap Reserve:       {}", self.size_of_heap_reserve)?;
        writeln!(f, "Size of Heap Commit:        {}", self.size_of_heap_commit)?;
        writeln!(f, "Loader Flags:               {}", self.loader_flags)?;
        writeln!(f, "Number of RVA and Sizes:    {}", self.number_of_rva_and_sizes)?;
        write!(f, "\n{}", self.data_directories)?;

        Ok(())
    }
}

/// The following values defined for the Subsystem field of the optional header 
/// determine which Windows subsystem (if any) is required to run the image.
#[derive(FromPrimitive, Debug)]
#[repr(u16)]
pub enum Subsystem {
    /// An unknown subsystem
    Unknown = 0,
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
    /// Bitflags that contain various information about
    /// how a given DLL should be loaded.
    pub struct DLLCharacteristics: u16 {
        /// Reserved, must be zero.
        const IMAGE_DLLCHARACTERISTICS_RESERVED1 = 0x0001;
        /// Reserved, must be zero.
        const IMAGE_DLLCHARACTERISTICS_RESERVED2 = 0x0002;
        /// Reserved, must be zero.
        const IMAGE_DLLCHARACTERISTICS_RESERVED4 = 0x0004;
        /// Reserved, must be zero.
        const IMAGE_DLLCHARACTERISTICS_RESERVED8 = 0x0008;
        /// Image can handle a high entropy 64-bit virtual address space.
        const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020;
        /// DLL can be relocated at load time.
        const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040;
        /// Code Integrity checks are enforced.
        const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080;
        /// Image is NX compatible.
        const IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100;
        /// Isolation aware, but do not isolate the image.
        const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200;
        /// Does not use structured exception (SE) handling. 
        /// No SE handler may be called in this image.
        const IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400;
        /// Do not bind the image.
        const IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800;
        /// Image must execute in an AppContainer.
        const IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000;
        /// A WDM driver.
        const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000;
        /// Image supports Control Flow Guard.
        const IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000;
        /// Terminal Server aware.
        const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000;
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

/// Helper functions for optional header structs
pub trait Optional: Sized {
    /// Returns the subsystem as an enum
    fn get_subsystem(&self) -> Option<Subsystem>;
    /// Returns the DLL Characteristics as bitflags
    fn get_dll_characteristics(&self) -> Option<DLLCharacteristics>;
    /// Parse optional header (either PE32, or PE32+) starting at
    /// the given offset.
    fn parse_optional_header(binary: &[u8], offset: &mut usize) -> Result<Self, Error>;
}

impl Optional for OptionalHeader32 {
    fn get_subsystem(&self) -> Option<Subsystem> {
        Subsystem::from_u16(self.subsystem)
    }

    fn get_dll_characteristics(&self) -> Option<DLLCharacteristics> {
        DLLCharacteristics::from_bits(self.dll_characteristics)
    }

    fn parse_optional_header(binary: &[u8], offset: &mut usize) -> Result<Self, Error> {
        let size = size_of::<Self>();
        let slice = match binary.get(*offset..*offset+size) {
            Some(slice) => slice,
            None => {
                return Err(Error::OffsetOutOfRange);
            }
        };

        let optional_header = try_from_bytes::<OptionalHeader32>(slice);
        *offset += size;

        match optional_header.copied() {
            Ok(header) => {
                Ok(header)
            }
            Err(_) => {
                Err(Error::BadOptionalHeader)
            }
        }
    }
}

impl Optional for OptionalHeader64 {
    fn get_subsystem(&self) -> Option<Subsystem> {
        Subsystem::from_u16(self.subsystem)
    }

    fn get_dll_characteristics(&self) -> Option<DLLCharacteristics> {
        DLLCharacteristics::from_bits(self.dll_characteristics)
    }

    fn parse_optional_header(binary: &[u8], offset: &mut usize) -> Result<Self, Error> {
        let size = size_of::<Self>();
        let slice = match binary.get(*offset..*offset+size) {
            Some(slice) => slice,
            None => {
                return Err(Error::OffsetOutOfRange);
            }
        };
    
        let optional_header = try_from_bytes::<OptionalHeader64>(slice);
        *offset += size;
        match optional_header.copied() {
            Ok(header) => {
                Ok(header)
            }
            Err(_) => {
                Err(Error::BadOptionalHeader)
            }
        }
    }
}