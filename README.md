# [PE Parser](https://docs.rs/crate/pe-parser/latest)
> A blazing fast 🔥 PE Parser written in Rust

## Motivation
The main goals of `pe-parser` is to write something suitable for a PE Loader.

## Is editing supported?
Currently no, but it wouldn't be too difficult to add from the current backbone.

As for weird or unusual PEs, as long as the PE conforms to the standard outlined in Microsoft's documentation, it should read fine. Malformed PEs would likely run into issues of either returning an error or misreading data, but I don't think it will outright panic.

As for the stuff currently not parsed, I think the main ones I want to focus on are the .edata and .idata sections, as they can be particularly useful when examining DLLs. Stuff like the COFF relocations, strings, symbols etc..., are less of a priority since they're deprecated.

As per your suggestion, I'll include this info in the README.

Other stuff I want to improve is its functionality as a library, not just a CLI tool, and ofc documentation. I've added comments for every field I could on all the structs and enums etc... but currently, I'm lacking some basic "how-to" documentation.

What is parsed right now:
- COFF Header
- Optional Header
- Data Directories
- Section Tables/Headers

What is not parsed yet:
- COFF Relocations
- COFF Line Numbers
- COFF Symbol Table
- COFF String Table
- Certificate Table
- Delay-Load Import Table
- .debug Section
- .drectve Section
- .edata Section
- .idata Section
- .pdata Section
- .reloc Section
- .tls Section
- Load Config Structure
- .rsrc Section
- .cormeta Section
- .sxdata Section
