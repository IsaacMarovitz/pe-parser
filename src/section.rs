use bytemuck::checked::try_from_bytes;
use bytemuck::{Pod, Zeroable};
use bitflags::bitflags;
use core::{fmt, str};
use core::writeln;
use crate::prelude::*;

/// Parse the section table from a byte array at a given offset.
/// `number_of_sections` should be equal to number of sections
/// defined in the COFF header.
pub fn parse_section_table(binary: &[u8], offset: usize, number_of_sections: u16) -> Vec<section_header> {
    let mut offset = offset;
    let mut headers: Vec<section_header> = Vec::new();
    let header_size = core::mem::size_of::<section_header>();

    for _ in 0..number_of_sections {
        if let Some(slice) = binary.get(offset..offset+header_size) {
            if let Some(header) = try_from_bytes::<section_header>(slice).ok() {
                headers.push(*header);
            }
        }
        offset += header_size;
    }

    headers
}

/// Contains information such as name, size, characteristics
/// and location of a section in the binary
#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct section_header {
    /// An 8-byte, null-padded UTF-8 encoded string. 
    /// If the string is exactly 8 characters long, there is no terminating null. 
    /// For longer names, this field contains a slash (/) that is followed by an ASCII representation of a decimal number that is an offset into the string table. 
    /// Executable images do not use a string table and do not support section names longer than 8 characters. 
    /// Long names in object files are truncated if they are emitted to an executable file.
    pub name: [u8; 8],
    /// The total size of the section when loaded into memory. 
    /// If this value is greater than `size_of_raw_data`, the section is zero-padded. 
    /// This field is valid only for executable images and should be set to zero for object files.
    pub virtual_size: u32,
    /// For executable images, the address of the first byte of the section relative to the image base when the section is loaded into memory.
    /// For object files, this field is the address of the first byte before relocation is applied; for simplicity, compilers should set this to zero.
    /// Otherwise, it is an arbitrary value that is subtracted from offsets during relocation.
    pub virtual_address: u32,
    /// The size of the section (for object files) or the size of the initialized data on disk (for image files).
    /// For executable images, this must be a multiple of `file_alignment` from the optional header.
    /// If this is less than `virtual_size`, the remainder of the section is zero-filled.
    /// Because the `size_of_raw_data` field is rounded but the `virtual_size` field is not, it is possible for `size_of_raw_data` to be greater than `virtual_size` as well.
    /// When a section contains only uninitialized data, this field should be zero.
    pub size_of_raw_data: u32,
    /// The file pointer to the first page of the section within the COFF file.
    /// For executable images, this must be a multiple of `file_alignment` from the optional header.
    /// For object files, the value should be aligned on a 4-byte boundary for best performance.
    /// When a section contains only uninitialized data, this field should be zero.
    pub pointer_to_raw_data: u32,
    /// The file pointer to the beginning of relocation entries for the section.
    /// This is set to zero for executable images or if there are no relocations.
    pub pointer_to_relocations: u32,
    /// The file pointer to the beginning of line-number entries for the section.
    /// This is set to zero if there are no COFF line numbers.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    pub pointer_to_linenumbers: u32,
    /// The number of relocation entries for the section.
    /// This is set to zero for executable images.
    pub number_of_relocations: u16,
    /// The number of line-number entries for the section.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    pub number_of_linenumbers: u16,
    /// The flags that describe the characteristics of the section.
    pub characteristics: u32
}

impl fmt::Display for section_header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.get_name()
            .expect("Failed to get name");
        let characteristics = self.get_characteristics()
            .expect("Failed to get characteristics");

        writeln!(f, "Section Header")?;
        writeln!(f, "--------------")?;
        writeln!(f, "Name:                    {:?}", name)?;
        writeln!(f, "Virtual Size:            {}", self.virtual_size)?;
        writeln!(f, "Virtual Address:         {:#010x}", self.virtual_address)?;
        writeln!(f, "Size of Raw Data:        {}", self.size_of_raw_data)?;
        writeln!(f, "Pointer to Raw Data:     {}", self.pointer_to_raw_data)?;
        writeln!(f, "Pointer to Relocations:  {}", self.pointer_to_relocations)?;
        writeln!(f, "Pointer to Line-numbers: {}", self.pointer_to_linenumbers)?;
        writeln!(f, "Number of Relocations:   {}", self.number_of_relocations)?;
        writeln!(f, "Number of Line-numbers:  {}", self.number_of_linenumbers)?;
        writeln!(f, "Characteristics:         {}", characteristics)?;

        Ok(())
    }
}

bitflags! {
    /// Bitflags that contain various information about
    /// how a section should be loaded
    pub struct SectionFlags: u32 {
        /// Reserved for future use.
        const IMAGE_SCN_RESERVED0 = 0x00000000;
        /// Reserved for future use.
        const IMAGE_SCN_RESERVED1 = 0x00000001;
        /// Reserved for future use.
        const IMAGE_SCN_RESERVED2 = 0x00000002;
        /// Reserved for future use.
        const IMAGE_SCN_RESERVED4 = 0x00000004;
        /// The section should not be padded to the next boundary.
        /// This flag is obsolete and is replaced by `align1Bytes`.
        /// This is valid only for object files.
        const IMAGE_SCN_TYPE_NO_PAD = 0x00000008;
        /// Reserved for future use.
        const IMAGE_SCN_RESERVED10 = 0x00000010;
        /// The section contains executable code.
        const IMAGE_SCN_CNT_CODE = 0x00000020;
        /// The section contains initialized data.
        const IMAGE_SCN_CNT_INITALIZED_DATA = 0x00000040;
        /// The section contains uninitialized data.
        const IMAGE_SCN_CNT_UNINITALIZED_DATA = 0x00000080;
        /// Reserved for future use.
        const IMAGE_SCN_LNK_OTHER = 0x00000100;
        /// The section contains comments or other information.
        /// The .drectve section has this type.
        /// This is valid for object files only.
        const IMAGE_SCN_LNK_INFO = 0x00000200;
        /// Reserved for future use.
        const IMAGE_SCN_RESERVED400 = 0x00000400;
        /// The section will not become part of the image.
        /// This is valid only for object files.
        const IMAGE_SCN_LNK_REMOVE = 0x00000800;
        /// The section contains COMDAT data. 
        /// This is valid only for object files.
        const IMAGE_SCN_LNK_COMDAT = 0x00001000;
        /// The section contains data referenced through the global pointer (GP).
        const IMAGE_SCN_GPREL = 0x00008000;
        /// Reserved for future use.
        const IMAGE_SCN_MEM_PURGABLE = 0x00020000;
        /// Reserved for future use.
        const IMAGE_SCN_MEM_16BIT = 0x00020000;
        /// Reserved for future use.
        const IMAGE_SCN_MEM_LOCKED = 0x00040000;
        /// Reserved for future use.
        const IMAGE_SCN_MEM_PRELOAD = 0x00080000;
        /// Align data on a 1-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
        /// Align data on a 2-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
        /// Align data on a 4-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
        /// Align data on a 8-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
        /// Align data on a 16-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
        /// Align data on a 32-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
        /// Align data on a 64-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
        /// Align data on a 128-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
        /// Align data on a 256-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
        /// Align data on a 512-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
        /// Align data on a 1024-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
        /// Align data on a 2048-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
        /// Align data on a 4096-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
        /// Align data on a 8192-byte boundary.
        /// Valid only for object files.
        const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
        /// The section contains extended relocations.
        /// `lnkNrelocOvfl` indicates that the count of relocations for the section exceeds the 16 bits that are reserved for it in the section header.
        /// If the bit is set and the `number_of_relocations` field in the section header is 0xffff, the actual relocation count is stored in the 32-bit `virtual_address` field of the first relocation.
        /// It is an error if `lnkNrelocOvfl` is set and there are fewer than 0xffff relocations in the section.
        const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
        /// The section can be discarded as needed.
        const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        /// The section cannot be cached.
        const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        /// The section is not pageable.
        const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
        /// The section can be shared in memory.
        const IMAGE_SCN_MEM_SHARED = 0x10000000;
        /// The section can be executed as code.
        const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        /// The section can be read.
        const IMAGE_SCN_MEM_READ = 0x40000000;
        /// The section can be written to.
        const IMAGE_SCN_MEM_WRITE = 0x80000000;
    }
}

// Allow SectionFlags flags to be easily printed
impl fmt::Debug for SectionFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for SectionFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl str::FromStr for SectionFlags {
    type Err = bitflags::parser::ParseError;

    fn from_str(flags: &str) -> Result<Self, Self::Err> {
        Ok(Self(flags.parse()?))
    }
}

impl section_header {
    /// Get the name of a section as a string.
    /// Note that this string may contain null characters.
    pub fn get_name(&self) -> Option<String> {
        String::from_utf8(self.name.to_vec()).ok()
    }

    /// Returns the Section Characteristics as bitflags
    pub fn get_characteristics(&self) -> Option<SectionFlags> {
        SectionFlags::from_bits(self.characteristics)
    }
}