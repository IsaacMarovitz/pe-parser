use bytemuck::{Pod, Zeroable};
use num_derive::FromPrimitive;    

#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct COFF_file_header {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characterisitcs: u16
}

#[derive(FromPrimitive, Debug)]
#[repr(u16)]
pub enum MachineTypes {
    Unkown = 0x0,
    Alpha = 0x184,
    Alpha64 = 0x284,
    AM33 = 0x1d3,
    AMD64 = 0x8664,
    ARM = 0x1c0,
    ARM64 = 0xaa64,
    ARMNT = 0x1c4,
    EBC = 0xebc,
    I386 = 0x14c,
    IA64 = 0x200,
    LoongArch32 = 0x6232,
    LoongArch64 = 0x6264,
    M32R = 0x9041,
    MIPS16 = 0x266,
    MIPSFPU = 0x366,
    MIPSFPU16 = 0x466,
    PowerPC = 0x1f0,
    PowerPCFP = 0x1f1,
    R4000 = 0x166,
    RISCV32 = 0x5032,
    RISCV64 = 0x5064,
    RISCV128 = 0x5128,
    SH3 = 0x1a2,
    SH3DSP = 0x1a3,
    SH4 = 0x1a6,
    SH5 = 0x1a8,
    Thunb = 0x1c2,
    WCEMIPSV2 = 0x169
}
