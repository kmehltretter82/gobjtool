// SPDX-License-Identifier: GPL-2.0-or-later
//
// gobjtool: a native Goose implementation of Linux objtool.
// The first vertical slice is a strict ELF64/x86-64 relocatable-object reader
// plus a Linux-table-derived native x86-64 instruction decoder.
import std;
import os;
import .analysis;
import .elf;

fn usage() {
    write_stderr("usage: gobjtool <check|inspect|decode> FILE\n");
    exit(2);
}

fn inspect(sections: elf::Section[:], symbols: elf::Symbol[:],
           relocations: elf::Relocation[:]) {
    print("ELF64 x86-64 ET_REL sections=", sections.len,
          " symbols=", symbols.len, " relocations=", relocations.len);
    for section in sections {
        print("section index=", section.index, " name=", section.name,
              " type=", elf::section_kind_name(section.kind),
              " offset=", section.offset, " size=", section.size,
              " link=", section.link, " info=", section.info);
    }
    for symbol in symbols {
        print("symbol table=", symbol.table_section, " index=", symbol.index,
              " name=", symbol.name, " section=", symbol.section_index,
              " value=", symbol.value, " size=", symbol.size,
              " bind=", symbol.info >> 4, " type=", symbol.info & 15);
    }
    for relocation in relocations {
        print("relocation section=", relocation.relocation_section,
              " index=", relocation.index,
              " target=", relocation.target_section,
              " offset=", relocation.offset,
              " symbol=", relocation.symbol_index,
              " type=", relocation.kind,
              " addend=", relocation.addend,
              " form=", if relocation.has_addend { "RELA" } else { "REL" });
    }
}

fn main() {
    let argv = args();
    if argv.len == 2 && argv[1] == "--version" {
        print("gobjtool 0.1.0");
        return;
    }
    if argv.len != 3 || (argv[1] != "check" && argv[1] != "inspect" &&
                         argv[1] != "decode") {
        usage();
    }

    var data: u8[>..] = [];
    if !read_file(argv[2], data) {
        write_stderr(str("gobjtool: cannot read ", argv[2], "\n"));
        exit(1);
    }

    var sections: elf::Section[>..] = [];
    var symbols: elf::Symbol[>..] = [];
    var relocations: elf::Relocation[>..] = [];
    let header, ok, error = elf::parse(data, sections, symbols, relocations);
    if !ok {
        write_stderr(str(error, "\n"));
        exit(1);
    }
    if argv[1] == "inspect" {
        inspect(sections, symbols, relocations);
    } else {
        let stats, analysis_ok, analysis_error = analysis::build(
            data, sections, relocations, argv[1] == "decode");
        if !analysis_ok {
            write_stderr(str("gobjtool: ", analysis_error, "\n"));
            exit(1);
        }
    }
}
