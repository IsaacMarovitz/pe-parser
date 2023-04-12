use bytemuck::{Pod, Zeroable};
use num_derive::FromPrimitive;   
use num_traits::FromPrimitive;
use bitflags::bitflags;
use std::{fmt, str};

// COFF File Header (Object and Image)
#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct coff_file_header {
    /// The number that identifies the type of target machine.
    pub machine: u16,
    /// The number of sections. This indicates the size of the section table, which immediately follows the headers.
    pub number_of_sections: u16,
    /// The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), which indicates when the file was created.
    pub time_date_stamp: u32,
    /// The file offset of the COFF symbol table, or zero if no COFF symbol table is present.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    pub pointer_to_symbol_table: u32,
    /// The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    pub number_of_symbols: u32,
    /// The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file.
    pub size_of_optional_header: u16,
    /// The flags that indicate the attributes of the file.
    pub characterisitcs: u16
}

impl fmt::Display for coff_file_header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let machine_type = MachineTypes::from_u16(self.machine)
            .expect("Failed to get machine type");
        let characteristics = Characteristics::from_bits(self.characterisitcs)
            .expect("Failed to get characterisitcs");

        writeln!(f, "COFF Header")?;
        writeln!(f, "-----------")?;
        writeln!(f, "Machine Type: {:?}", machine_type)?;
        writeln!(f, "Number of Sections: {}", self.number_of_sections)?;
        writeln!(f, "Size of Optional Header: {}", self.size_of_optional_header)?;
        writeln!(f, "Characteristics: {}", characteristics)?;

        fmt::Result::Ok(())
    }
}

/// The Machine field has one of the following values, which specify the CPU type. 
/// An image file can be run only on the specified machine or on a system that emulates the specified machine.
#[derive(FromPrimitive, Debug)]
#[repr(u16)]
pub enum MachineTypes {
    /// The content of this field is assumed to be applicable to any machine type
    Unkown = 0x0,
    /// Alpha AXP, 32-bit address space
    Alpha = 0x184,
    /// Alpha 64/AXP 64, 64-bit address space
    Alpha64 = 0x284,
    /// Matsushita AM33
    AM33 = 0x1d3,
    /// x64
    AMD64 = 0x8664,
    /// ARM little endian
    ARM = 0x1c0,
    /// ARM64 little endian
    ARM64 = 0xaa64,
    /// ARM Thumb-2 little endian
    ARMNT = 0x1c4,
    /// EFI byte code
    EBC = 0xebc,
    /// Intel 386 or later processors and compatible processors
    I386 = 0x14c,
    /// Intel Itanium processor family
    IA64 = 0x200,
    /// LoongArch 32-bit processor family
    LoongArch32 = 0x6232,
    /// LoongArch 64-bit processor family
    LoongArch64 = 0x6264,
    /// Mitsubishi M32R little endian
    M32R = 0x9041,
    /// MIPS16
    MIPS16 = 0x266,
    /// MIPS with FPU
    MIPSFPU = 0x366,
    /// MIPS16 with FPU
    MIPSFPU16 = 0x466,
    /// Power PC little endian
    PowerPC = 0x1f0,
    /// Power PC with floating point support
    PowerPCFP = 0x1f1,
    /// MIPS little endian
    R4000 = 0x166,
    /// RISC-V 32-bit address space
    RISCV32 = 0x5032,
    /// RISC-V 64-bit address space
    RISCV64 = 0x5064,
    /// RISC-V 128-bit address space
    RISCV128 = 0x5128,
    /// Hitachi SH3
    SH3 = 0x1a2,
    /// Hitachi SH3 DSP
    SH3DSP = 0x1a3,
    /// Hitachi SH4
    SH4 = 0x1a6,
    /// Hitachi SH5
    SH5 = 0x1a8,
    /// Thumb
    Thunb = 0x1c2,
    /// MIPS little-endian WCE v2
    WCEMIPSV2 = 0x169
}

bitflags! {
    /// The Characteristics field contains flags that indicate attributes of the object or image file.
    pub struct Characteristics: u16 {
        /// Image only, Windows CE, and Microsoft Windows NT and later.
        /// This indicates that the file does not contain base relocations and must therefore be loaded at its preferred base address.
        /// If the base address is not available, the loader reports an error.
        /// The default behavior of the linker is to strip base relocations from executable (EXE) files.
        const imageFileRelocsStripped = 0x0001;
        /// Image only. This indicates that the image file is valid and can be run.
        /// If this flag is not set, it indicates a linker error.
        const imageFileExecutableImage = 0x0002;
        /// COFF line numbers have been removed. This flag is deprecated and should be zero.
        const imageFileLineNumsStripped = 0x0004;
        /// COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
        const imageFileLocalSymsStripped = 0x0008;
        /// Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
        const imageFileAggresiveWsTrim = 0x0010;
        /// Application can handle > 2-GB addresses.
        const imageFileLargeAddressAware = 0x0020;
        /// This flag is reserved for future use.
        const imageFileReserved1 = 0x0040;
        /// Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory.
        /// This flag is deprecated and should be zero.
        const imageFileBytesReservedLo = 0x0080;
        /// Machine is based on a 32-bit-word architecture.
        const imageFile32bitMachine = 0x0100;
        /// Debugging information is removed from the image file.
        const imageFileDebugStripped = 0x0200;
        /// If the image is on removable media, fully load it and copy it to the swap file.
        const imageFileRemovableRunFromSwap = 0x0400;
        /// If the image is on network media, fully load it and copy it to the swap file.
        const imageFileNetRunFromSwap = 0x0800;
        /// The image file is a system file, not a user program.
        const imageFileSystem = 0x1000;
        /// The image file is a dynamic-link library (DLL).
        /// Such files are considered executable files for almost all purposes, although they cannot be directly run.
        const imageFileDll = 0x2000;
        /// The file should be run only on a uniprocessor machine.
        const imageFileUpSystemOnly = 0x4000;
        /// Big endian: the MSB precedes the LSB in memory. 
        /// This flag is deprecated and should be zero.
        const imageFileBytesReservedHi = 0x8000;
    }
}

// Allow Characteristics flags to be easily printed
impl fmt::Debug for Characteristics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Characteristics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl str::FromStr for Characteristics {
    type Err = bitflags::parser::ParseError;

    fn from_str(flags: &str) -> Result<Self, Self::Err> {
        Ok(Self(flags.parse()?))
    }
}