# [PE Parser](https://docs.rs/crate/pe-parser/latest)

[![Build & Test](https://github.com/IsaacMarovitz/pe-parser/actions/workflows/rust.yml/badge.svg)](https://github.com/IsaacMarovitz/pe-parser/actions/workflows/rust.yml) 
[![Fuzz](https://github.com/IsaacMarovitz/pe-parser/actions/workflows/fuzz.yml/badge.svg)](https://github.com/IsaacMarovitz/pe-parser/actions/workflows/fuzz.yml)

A blazing fast 🔥 PE Parser written in Rust

## Motivation
The main goals of `pe-parser` is to write something suitable for a PE Loader.

## Is editing supported?
Currently no, but it wouldn't be too difficult to add from the current backbone.

## How does it handle unsual or malformed PEs?
As long as the PE conforms to the standard outlined in Microsoft's documentation, it should read fine. Malformed PEs would likely run into issues of either returning an error or misreading data.

## What is parsed right now?
- COFF Header
- Optional Header
- Data Directories
- Section Tables/Headers

## What is not parsed yet?
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
