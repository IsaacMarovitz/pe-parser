use std::{env, fs};
use bytemuck::{Pod, Zeroable, from_bytes};
use num_derive::FromPrimitive;    
use num_traits::FromPrimitive;

const IMAGE_DOS_PE_SIGNATURE_OFFSET: usize = 0x3c;

#[derive(Copy, Clone, Pod, Zeroable, Default)]
#[repr(C)]
pub struct COFF_file_header {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characterisitcs: u16
}

#[derive(FromPrimitive, Debug)]
enum MachineTypes {
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

fn main() {
    let args: Vec<String> = env::args().collect();

    let file_path = &args[1];
    let binary = fs::read(file_path)
        .expect("Failed to read file");

    let pe_offset = binary[IMAGE_DOS_PE_SIGNATURE_OFFSET] as usize;
    let string = binary.read_string(pe_offset, 4);

    let header = from_bytes::<COFF_file_header>(&binary[pe_offset+4..pe_offset + 4 +20]);
    let machine_type = MachineTypes::from_u16(header.machine)
        .expect("Failed to get machine type");
    println!("{:?}", machine_type);
}

impl Scribe for Vec<u8> {
    fn read_u8(&self, offset: usize) -> u8 {
        self[offset]
    }

    fn read_u16(&self, offset: usize) -> u16 {
        u16::from_le_bytes(self[offset..offset+2]
            .try_into()
            .expect("Failed to get u16 value!"))
    }

    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self[offset..offset+4]
            .try_into()
            .expect("Failed to get u16 value!"))
    }

    fn read_string(&self, offset: usize, size: usize) -> String {
        String::from_utf8(self[offset..offset+size].to_vec())
            .expect("Failed to get string")
    }
}

pub trait Scribe {
    fn read_u8(&self, offset: usize) -> u8;
    fn read_u16(&self, offset: usize) -> u16;
    fn read_u32(&self, offset: usize) -> u32;
    fn read_string(&self, offset: usize, size: usize) -> String;
}