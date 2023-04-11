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