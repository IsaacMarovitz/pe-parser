use num_derive::FromPrimitive;

/// Relocation type indicators for x64 and compatible processors.
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u16)]
pub enum X86RelocationType {
    /// The relocation is ignored.
    Absolute = 0x0000,
    /// The 64-bit VA of the relocation target.
    Addr64 = 0x0001,
    /// The 32-bit VA of the relocation target.
    Addr32 = 0x0002,
    /// The 32-bit address without an image base (RVA).
    Addr32Nb = 0x0003,
    /// The 32-bit relative address from the byte following the relocation.
    Rel32 = 0x0004,
    /// The 32-bit address relative to byte distance 1 from the relocation.
    Rel321 = 0x0005,
    /// The 32-bit address relative to byte distance 2 from the relocation.
    Rel322 = 0x0006,
    /// The 32-bit address relative to byte distance 3 from the relocation.
    Rel323 = 0x0007,
    /// The 32-bit address relative to byte distance 4 from the relocation.
    Rel324 = 0x0008,
    /// The 32-bit address relative to byte distance 5 from the relocation.
    Rel325 = 0x0009,
    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    Section = 0x000A,
    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    SecRel = 0x000B,
    /// A 7-bit unsigned offset from the base of the section that contains the target.
    SecRel7 = 0x000C,
    /// CLR tokens.
    Token = 0x000D,
    /// A 32-bit signed span-dependent value emitted into the object.
    SRel32 = 0x000E,
    /// A pair that must immediately follow every span-dependent value.
    Pair = 0x000F,
    /// A 32-bit signed span-dependent value that is applied at link time.
    SSpan32 = 0x0010,
}

/// Relocation type indicators for ARM processors.
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u16)]
pub enum ARMRelocationType {
    /// The relocation is ignored.
    Absolute = 0x0000,
    /// The 32-bit VA of the target.
    Addr32 = 0x0001,
    /// The 32-bit RVA of the target.
    Addr32Nb = 0x0002,
    /// The 24-bit relative displacement to the target.
    Branch24 = 0x0003,
    /// The reference to a subroutine call.
    /// The reference consists of two 16-bit instructions with 11-bit offsets.
    Branch11 = 0x0004,
    /// The 32-bit relative address from the byte following the relocation.
    Rel32 = 0x000A,
    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    Section = 0x000E,
    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    SecRel = 0x000F,
    /// The 32-bit VA of the target.
    /// This relocation is applied using a MOVW instruction for the low 16 bits followed by a MOVT for the high 16 bits.
    Mov32 = 0x0010,
    /// The 32-bit VA of the target.
    /// This relocation is applied using a MOVW instruction for the low 16 bits followed by a MOVT for the high 16 bits.
    ImageRelThumbMOV32 = 0x0011,
    /// The instruction is fixed up with the 21-bit relative displacement to the 2-byte aligned target.
    /// The least significant bit of the displacement is always zero and is not stored.
    /// This relocation corresponds to a Thumb-2 32-bit conditional B instruction.
    ImageRelThumbBranch20 = 0x0012,
    /// Unused relocation type.
    Unused = 0x0013,
    /// The instruction is fixed up with the 25-bit relative displacement to the 2-byte aligned target.
    /// The least significant bit of the displacement is zero and is not stored.
    /// This relocation corresponds to a Thumb-2 B instruction.
    ImageRelThumbBranch24 = 0x0014,
    /// The instruction is fixed up with the 25-bit relative displacement to the 4-byte aligned target.
    /// The low 2 bits of the displacement are zero and are not stored.
    /// This relocation corresponds to a Thumb-2 BLX instruction.
    ImageRelThumbBLX23 = 0x0015,
    /// The relocation is valid only when it immediately follows a ARM_REFHI or THUMB_REFHI.
    /// Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    Pair = 0x0016,
}

/// Relocation type indicators for ARM64 processors.
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u16)]
pub enum ARM64RelocationType {
    /// The relocation is ignored.
    Absolute = 0x0000,
    /// The 32-bit VA of the target.
    Addr32 = 0x0001,
    /// The 32-bit RVA of the target.
    Addr32Nb = 0x0002,
    /// The 26-bit relative displacement to the target, for B and BL instructions.
    Branch26 = 0x0003,
    /// The page base of the target, for ADRP instruction.
    PageBaseRel21 = 0x0004,
    /// The 12-bit relative displacement to the target, for instruction ADR.
    Rel21 = 0x0005,
    /// The 12-bit page offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    PageOffset12A = 0x0006,
    /// The 12-bit page offset of the target, for instruction LDR (indexed, unsigned immediate).
    PageOffset12L = 0x0007,
    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    SecRel = 0x0008,
    /// Bit 0:11 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    SecRelLow12A = 0x0009,
    /// Bit 12:23 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
    SecRelHigh12A = 0x000A,
    /// Bit 0:11 of section offset of the target, for instruction LDR (indexed, unsigned immediate).
    SecRelLow12L = 0x000B,
    /// CLR token.
    Token = 0x000C,
    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    Section = 0x000D,
    /// The 64-bit VA of the relocation target.
    Addr64 = 0x000E,
    /// The 19-bit offset to the relocation target, for conditional B instruction.
    Branch19 = 0x000F,
    /// The 14-bit offset to the relocation target, for instructions TBZ and TBNZ.
    Branch14 = 0x0010,
    /// The 32-bit relative address from the byte following the relocation.
    Rel32 = 0x0011,
}

/// Relocation type indicators for SH3 and SH4 processors.
/// SH5-specific relocations are noted as SHM (SH Media).
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u16)]
pub enum SuperHRelocationType {
    /// The relocation is ignored.
    Absolute = 0x0000,
    /// A reference to the 16-bit location that contains the VA of the target symbol.
    Direct16 = 0x0001,
    /// The 32-bit VA of the target symbol.
    Direct32 = 0x0002,
    /// A reference to the 8-bit location that contains the VA of the target symbol.
    Direct8 = 0x0003,
    /// A reference to the 8-bit instruction that contains the effective 16-bit VA of the target symbol.
    Direct8Word = 0x0004,
    /// A reference to the 8-bit instruction that contains the effective 32-bit VA of the target symbol.
    Direct8Long = 0x0005,
    /// A reference to the 8-bit location whose low 4 bits contain the VA of the target symbol.
    Direct4 = 0x0006,
    /// A reference to the 8-bit instruction whose low 4 bits contain the effective 16-bit VA of the target symbol.
    Direct4Word = 0x0007,
    /// A reference to the 8-bit instruction whose low 4 bits contain the effective 32-bit VA of the target symbol.
    Direct4Long = 0x0008,
    /// A reference to the 8-bit instruction that contains the effective 16-bit relative offset of the target symbol.
    PCRel8Word = 0x0009,
    /// A reference to the 8-bit instruction that contains the effective 32-bit relative offset of the target symbol.
    PCRel8Long = 0x000A,
    /// A reference to the 16-bit instruction whose low 12 bits contain the effective 16-bit relative offset of the target symbol.
    PCRel12Word = 0x000B,
    /// A reference to a 32-bit location that is the VA of the section that contains the target symbol.
    StartOfSection = 0x000C,
    /// A reference to the 32-bit location that is the size of the section that contains the target symbol.
    SizeOfSection = 0x000D,
    /// The 16-bit section index of the section that contains the target. This is used to support debugging information.
    Section = 0x000E,
    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    SecRel = 0x000F,
    /// The 32-bit RVA of the target symbol.
    Direct32Nb = 0x0010,
    /// GP relative.
    GPRel4Long = 0x0011,
    /// CLR token.
    Token = 0x0012,
    /// The offset from the current instruction in longwords.
    /// If the NOMODE bit is not set, insert the inverse of the low bit at bit 32 to select PTA or PTB.
    SHMPCRelPT = 0x0013,
    /// The low 16 bits of the 32-bit address.
    SHMRefLo = 0x0014,
    /// The high 16 bits of the 32-bit address.
    SHMRefHalf = 0x0015,
    /// The low 16 bits of the relative address.
    SHMRelLo = 0x0016,
    /// The high 16 bits of the relative address.
    SHMRelHalf = 0x0017,
    /// The relocation is valid only when it immediately follows a REFHALF, RELHALF, or RELLO relocation.
    /// The SymbolTableIndex field of the relocation contains a displacement and not an index into the symbol table.
    SHMPair = 0x0018,
    /// The relocation ignores section mode.
    SHMNoMode = 0x8000,
}

/// Relocation type indicators for PowerPC processors.
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u16)]
pub enum PowerPCRelocationType {
    /// The relocation is ignored.
    Absolute = 0x0000,
    /// The 64-bit VA of the target.
    Addr64 = 0x0001,
    /// The 32-bit VA of the target.
    Addr32 = 0x0002,
    /// The low 24 bits of the VA of the target.
    /// This is valid only when the target symbol is absolute and can be sign-extended to its original value.
    Addr24 = 0x0003,
    /// The low 16 bits of the target's VA.
    Addr16 = 0x0004,
    /// The low 14 bits of the target's VA.
    /// This is valid only when the target symbol is absolute and can be sign-extended to its original value.
    Addr14 = 0x0005,
    /// A 24-bit PC-relative offset to the symbol's location.
    Rel24 = 0x0006,
    /// A 14-bit PC-relative offset to the symbol's location.
    Rel14 = 0x0007,
    /// The 32-bit RVA of the target.
    Addr32Nb = 0x000A,
    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    SecRel = 0x000B,
    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    Section = 0x000C,
    /// The 16-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    SecRel16 = 0x000F,
    /// The high 16 bits of the target's 32-bit VA.
    /// This is used for the first instruction in a two-instruction sequence that loads a full address.
    /// This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed
    /// 16-bit displacement that is added to the upper 16 bits that was taken from the location that is being relocated.
    RefHi = 0x0010,
    /// The low 16 bits of the target's VA.
    RefLo = 0x0011,
    /// A relocation that is valid only when it immediately follows a REFHI or SECRELHI relocation.
    /// Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    Pair = 0x0012,
    /// The low 16 bits of the 32-bit offset of the target from the beginning of its section.
    SecRelLo = 0x0013,
    /// The 16-bit signed displacement of the target relative to the GP register.
    GPRel = 0x0015,
    /// The CLR token.
    Token = 0x0016,
}

/// Relocation type indicators for Intel 386 processors.
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u16)]
pub enum I386RelocationType {
    /// The relocation is ignored.
    Absolute = 0x0000,
    /// Not supported.
    Dir16 = 0x0001,
    /// Not supported.
    Rel16 = 0x0002,
    /// The target's 32-bit VA.
    Dir32 = 0x0006,
    /// The target's 32-bit RVA.
    Dir32Nb = 0x0007,
    /// Not supported.
    Seg12 = 0x0009,
    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    Section = 0x000A,
    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    SecRel = 0x000B,
    /// The CLR token.
    Token = 0x000C,
    /// A 7-bit offset from the base of the section that contains the target.
    SecRel7 = 0x000D,
    /// The 32-bit relative displacement to the target.
    /// This supports the x86 relative branch and call instructions.
    Rel32 = 0x0014,
}

/// Relocation type indicators for the Intel Itanium processor family and compatible processors.
/// Note that relocations on instructions use the bundle's offset and slot number for the relocation offset.
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u16)]
pub enum IA64RelocationType {
    /// The relocation is ignored.
    Absolute = 0x0000,
    /// The instruction relocation can be followed by an ADDEND relocation whose value is added
    /// to the target address before it is inserted into the specified slot in the IMM14 bundle.
    /// The relocation target must be absolute or the image must be fixed.
    IMM14 = 0x0001,
    /// The instruction relocation can be followed by an ADDEND relocation whose value is added
    /// to the target address before it is inserted into the specified slot in the IMM22 bundle.
    /// The relocation target must be absolute or the image must be fixed.
    IMM32 = 0x0002,
    /// The slot number of this relocation must be one (1).
    /// The relocation can be followed by an ADDEND relocation whose value is added
    /// to the target address before it is stored in all three slots of the IMM64 bundle.
    IMM64 = 0x0003,
    /// The target's 32-bit VA.
    /// This is supported only for /LARGEADDRESSAWARE:NO images.
    Dir32 = 0x0004,
    /// The target's 64-bit VA.
    Dir64 = 0x0005,
    /// The instruction is fixed up with the 25-bit relative displacement to the 16-bit aligned target.
    /// The low 4 bits of the displacement are zero and are not stored.
    PCRel21B = 0x0006,
    /// The instruction is fixed up with the 25-bit relative displacement to the 16-bit aligned target.
    /// The low 4 bits of the displacement, which are zero, are not stored.
    PCRel21M = 0x0007,
    /// The LSBs of this relocation's offset must contain the slot number whereas the rest is the bundle address. The bundle is fixed up with the 25-bit relative displacement to the 16-bit aligned target.
    /// The low 4 bits of the displacement are zero and are not stored.
    PCRel21F = 0x0008,
    /// The instruction relocation can be followed by an ADDEND relocation whose value is added
    /// to the target address and then a 22-bit GP-relative offset that is calculated and applied to the GPREL22 bundle.
    GPRel22 = 0x0009,
    /// The instruction is fixed up with the 22-bit GP-relative offset to the target symbol's literal table entry.
    /// The linker creates this literal table entry based on this relocation and the ADDEND relocation that might follow.
    LTOff22 = 0x000A,
    /// The 16-bit section index of the section contains the target.
    /// This is used to support debugging information.
    Section = 0x000B,
    /// The instruction is fixed up with the 22-bit offset of the target from the beginning of its section.
    /// This relocation can be followed immediately by an ADDEND relocation, whose Value field contains the 32-bit unsigned offset of the target from the beginning of the section.
    SecRel22 = 0x000C,
    /// The slot number for this relocation must be one (1). The instruction is fixed up with the 64-bit offset of the target from the beginning of its section.
    /// This relocation can be followed immediately by an ADDEND relocation whose Value field contains the 32-bit unsigned offset of the target from the beginning of the section.
    SecRel64I = 0x000D,
    /// The address of data to be fixed up with the 32-bit offset of the target from the beginning of its section.
    SecRel32 = 0x000E,
    /// The target's 32-bit RVA.
    Dir32Nb = 0x0010,
    /// This is applied to a signed 14-bit immediate that contains the difference between two relocatable targets.
    /// This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    SRel14 = 0x0011,
    /// This is applied to a signed 22-bit immediate that contains the difference between two relocatable targets.
    /// This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    SRel22 = 0x0012,
    /// This is applied to a signed 32-bit immediate that contains the difference between two relocatable values.
    /// This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    SRel32 = 0x0013,
    /// This is applied to an unsigned 32-bit immediate that contains the difference between two relocatable values.
    /// This is a declarative field for the linker that indicates that the compiler has already emitted this value.
    URel32 = 0x0014,
    /// A 60-bit PC-relative fixup that always stays as a BRL instruction of an MLX bundle.
    PCRel60X = 0x0015,
    /// A 60-bit PC-relative fixup.
    /// If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MBB bundle with NOP.B in slot 1 and a 25-bit BR instruction (with the 4 lowest bits all zero and dropped) in slot 2.
    PCRel60B = 0x0016,
    /// A 60-bit PC-relative fixup.
    /// If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MFB bundle with NOP.F in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
    PCRel60F = 0x0017,
    /// A 60-bit PC-relative fixup.
    /// If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MIB bundle with NOP.I in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
    PCRel60I = 0x0018,
    /// A 60-bit PC-relative fixup.
    /// If the target displacement fits in a signed 25-bit field, convert the entire bundle to an MMB bundle with NOP.M in slot 1 and a 25-bit (4 lowest bits all zero and dropped) BR instruction in slot 2.
    PCRel60M = 0x0019,
    /// A 64-bit GP-relative fixup.
    IMMGPRel64 = 0x001A,
    /// A CLR token.
    Token = 0x001B,
    /// A 32-bit GP-relative fixup.
    GPRel32 = 0x001C,
    /// The relocation is valid only when it immediately follows one of the following relocations: IMM14, IMM22, IMM64, GPREL22, LTOFF22, LTOFF64, SECREL22, SECREL64I, or SECREL32.
    /// Its value contains the addend to apply to instructions within a bundle, not for data.
    AddEnd = 0x001F,
}

/// Relocation type indicators for MIPS processors.
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u16)]
pub enum MIPSRelocationType {
    /// The relocation is ignored.
    Absolute = 0x0000,
    /// The high 16 bits of the target's 32-bit VA.
    RefHalf = 0x0001,
    /// The target's 32-bit VA.
    RefWord = 0x0002,
    /// The low 26 bits of the target's VA.
    /// This supports the MIPS J and JAL instructions.
    JMPAddr = 0x0003,
    /// The high 16 bits of the target's 32-bit VA.
    /// This is used for the first instruction in a two-instruction sequence that loads a full address.
    /// This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
    RefHi = 0x0004,
    /// The low 16 bits of the target's VA.
    RefLo = 0x0005,
    /// A 16-bit signed displacement of the target relative to the GP register.
    GPRel = 0x0006,
    /// The same as `MIPSRelocationType::GPRel`.
    Literal = 0x0007,
    /// The 16-bit section index of the section contains the target.
    /// This is used to support debugging information.
    Section = 0x000A,
    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    SecRel = 0x000B,
    /// The low 16 bits of the 32-bit offset of the target from the beginning of its section.
    SecRelLo = 0x000C,
    /// The high 16 bits of the 32-bit offset of the target from the beginning of its section.
    /// A PAIR relocation must immediately follow this one.
    /// The SymbolTableIndex of the PAIR relocation contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
    SecRelHi = 0x000D,
    /// The low 26 bits of the target's VA.
    /// This supports the MIPS16 JAL instruction.
    JMPAddr16 = 0x0010,
    /// The target's 32-bit RVA.
    RefWordNb = 0x0022,
    /// The relocation is valid only when it immediately follows a REFHI or SECRELHI relocation.
    /// Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    Pair = 0x0025,
}

/// Relocation type indicators for Mitsubishi M32R processors.
#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u16)]
pub enum M32RRelocationType {
    /// The relocation is ignored.
    Absolute = 0x0000,
    /// The target's 32-bit VA.
    Addr32 = 0x0001,
    /// The target's 32-bit RVA.
    Addr32Nb = 0x0002,
    /// The target's 24-bit VA.
    Addr24 = 0x0003,
    /// The target's 16-bit offset from the GP register.
    GPRel16 = 0x0004,
    /// The target's 24-bit offset from the program counter (PC), shifted left by 2 bits and sign-extended.
    PCRel24 = 0x0005,
    /// The target's 16-bit offset from the PC, shifted left by 2 bits and sign-extended.
    PCRel16 = 0x0006,
    /// The target's 8-bit offset from the PC, shifted left by 2 bits and sign-extended.
    PCRel8 = 0x0007,
    /// The 16 MSBs of the target VA.
    RefHalf = 0x0008,
    /// The 16 MSBs of the target VA, adjusted for LSB sign extension.
    /// This is used for the first instruction in a two-instruction sequence that loads a full 32-bit address.
    /// This relocation must be immediately followed by a PAIR relocation whose SymbolTableIndex contains a signed 16-bit displacement that is added to the upper 16 bits that are taken from the location that is being relocated.
    RefHi = 0x0009,
    /// The 16 LSBs of the target VA.
    RefLo = 0x000A,
    /// The relocation must follow the REFHI relocation.
    /// Its SymbolTableIndex contains a displacement and not an index into the symbol table.
    Pair = 0x000B,
    /// The 16-bit section index of the section that contains the target.
    /// This is used to support debugging information.
    Section = 0x000C,
    /// The 32-bit offset of the target from the beginning of its section.
    /// This is used to support debugging information and static thread local storage.
    SecRel = 0x000D,
    /// The CLR token.
    Token = 0x000E,
}