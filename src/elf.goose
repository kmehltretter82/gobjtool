// SPDX-License-Identifier: GPL-2.0-or-later
//
// Native, checked ELF64 parsing for gobjtool.  No libelf types or pointers
// cross into this module: every string is a read-only slice of the input and
// every table is materialized in a Goose-owned grow-only array.
namespace elf;
import std;

let EI_NIDENT = 16;
let ELF_HEADER_SIZE = 64;
let ELF_SECTION_SIZE = 64;
let ELF_SYMBOL_SIZE = 24;
let ELF_RELA_SIZE = 24;
let ELF_REL_SIZE = 16;

let ET_REL: u16 = 1;
let EM_X86_64: u16 = 62;
let EV_CURRENT: u32 = 1;
let ELFCLASS64: u8 = 2;
let ELFDATA2LSB: u8 = 1;

let SHN_XINDEX: u16 = 0xffff;
let SHT_NULL: u32 = 0;
let SHT_SYMTAB: u32 = 2;
let SHT_STRTAB: u32 = 3;
let SHT_RELA: u32 = 4;
let SHT_NOBITS: u32 = 8;
let SHT_REL: u32 = 9;
let SHT_DYNSYM: u32 = 11;
let SHT_SYMTAB_SHNDX: u32 = 18;

struct Header {
    file_type: u16,
    machine: u16,
    version: u32,
    entry: u64,
    program_offset: u64,
    section_offset: u64,
    flags: u32,
    program_entry_size: u16,
    program_count: u16,
    section_count: i64,
    section_name_index: i64,
}

struct Section {
    index: i64,
    name_offset: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entry_size: u64,
    name: const u8[:],
}

struct Symbol {
    table_section: i64,
    index: i64,
    name_offset: u32,
    info: u8,
    other: u8,
    section_index: u32,
    value: u64,
    size: u64,
    name: const u8[:],
}

struct Relocation {
    relocation_section: i64,
    index: i64,
    target_section: u32,
    symbol_table: u32,
    offset: u64,
    symbol_index: u32,
    kind: u32,
    addend: i64,
    has_addend: bool,
}

fn empty_header() -> Header {
    Header {
        file_type: 0,
        machine: 0,
        version: 0,
        entry: 0,
        program_offset: 0,
        section_offset: 0,
        flags: 0,
        program_entry_size: 0,
        program_count: 0,
        section_count: 0,
        section_name_index: 0,
    }
}

fn range_ok(data: const u8[:], at: u64, size: u64) -> bool {
    let length = data.len as u64;
    at <= length && size <= length - at
}

fn product(a: u64, b: u64) -> u64, bool {
    if a != 0 && b > 0xffffffffffffffff / a { return 0, false; }
    return a * b, true;
}

fn read_u16(data: const u8[:], at: i64) -> u16, bool {
    if at < 0 || !range_ok(data, at as u64, 2) { return 0, false; }
    return data[at] | ((data[at + 1] as u16) << 8), true;
}

fn read_u32(data: const u8[:], at: i64) -> u32, bool {
    if at < 0 || !range_ok(data, at as u64, 4) { return 0, false; }
    return data[at] |
           ((data[at + 1] as u32) << 8) |
           ((data[at + 2] as u32) << 16) |
           ((data[at + 3] as u32) << 24), true;
}

fn read_u64(data: const u8[:], at: i64) -> u64, bool {
    if at < 0 || !range_ok(data, at as u64, 8) { return 0, false; }
    return data[at] |
           ((data[at + 1] as u64) << 8) |
           ((data[at + 2] as u64) << 16) |
           ((data[at + 3] as u64) << 24) |
           ((data[at + 4] as u64) << 32) |
           ((data[at + 5] as u64) << 40) |
           ((data[at + 6] as u64) << 48) |
           ((data[at + 7] as u64) << 56), true;
}

fn read_section(data: const u8[:], table: u64, entry_size: u16,
                index: i64) -> Section, bool {
    let empty = data[..0];
    let empty_section = Section {
        index: index,
        name_offset: 0,
        kind: 0,
        flags: 0,
        address: 0,
        offset: 0,
        size: 0,
        link: 0,
        info: 0,
        align: 0,
        entry_size: 0,
        name: empty,
    };
    if index < 0 { return empty_section, false; }
    let delta, delta_ok = product(index as u64, entry_size);
    if !delta_ok || table > 0xffffffffffffffff - delta {
        return empty_section, false;
    }
    let at = table + delta;
    if !range_ok(data, at, ELF_SECTION_SIZE) {
        return empty_section, false;
    }
    let pos = at as! i64;
    let name_offset, n_ok = read_u32(data, pos);
    let kind, k_ok = read_u32(data, pos + 4);
    let flags, f_ok = read_u64(data, pos + 8);
    let address, a_ok = read_u64(data, pos + 16);
    let offset, o_ok = read_u64(data, pos + 24);
    let size, s_ok = read_u64(data, pos + 32);
    let link, l_ok = read_u32(data, pos + 40);
    let info, i_ok = read_u32(data, pos + 44);
    let align, al_ok = read_u64(data, pos + 48);
    let size_of_entry, e_ok = read_u64(data, pos + 56);
    if !n_ok || !k_ok || !f_ok || !a_ok || !o_ok || !s_ok || !l_ok ||
            !i_ok || !al_ok || !e_ok {
        return empty_section, false;
    }
    return Section {
        index: index,
        name_offset: name_offset,
        kind: kind,
        flags: flags,
        address: address,
        offset: offset,
        size: size,
        link: link,
        info: info,
        align: align,
        entry_size: size_of_entry,
        name: empty,
    }, true;
}

fn string_at(data: const u8[:], strings: Section, offset: u32) -> const u8[:], bool {
    let empty = data[..0];
    if strings.kind != SHT_STRTAB || offset >= strings.size {
        return empty, false;
    }
    let start = strings.offset + offset;
    let limit = strings.offset + strings.size;
    if !range_ok(data, strings.offset, strings.size) { return empty, false; }
    var end = start;
    while end < limit && data[end as! i64] != 0 { end++; }
    if end == limit { return empty, false; }
    return data[(start as! i64)..(end as! i64)], true;
}

fn symbol_count(sections: Section[:], table_index: u32) -> u64, bool {
    if table_index >= sections.len { return 0, false; }
    let table = sections[table_index as i64];
    if (table.kind != SHT_SYMTAB && table.kind != SHT_DYNSYM) ||
            table.entry_size != ELF_SYMBOL_SIZE ||
            table.size % table.entry_size != 0 {
        return 0, false;
    }
    return table.size / table.entry_size, true;
}

fn full_symbol_section(data: const u8[:], sections: Section[:],
                       table_index: i64, symbol_index: i64,
                       raw_index: u16) -> u32, bool {
    if raw_index != SHN_XINDEX { return raw_index, true; }
    var found = false;
    var result: u32 = 0;
    for ext in sections {
        if ext.kind == SHT_SYMTAB_SHNDX && ext.link == table_index {
            if found || ext.entry_size != 4 || ext.size % 4 != 0 ||
                    symbol_index as u64 >= ext.size / 4 {
                return 0, false;
            }
            let value, ok = read_u32(data,
                (ext.offset + symbol_index as u64 * 4) as! i64);
            if !ok { return 0, false; }
            result = value;
            found = true;
        }
    }
    return result, found;
}

fn parse(data: const u8[:], sections: Section[>..]&,
         symbols: Symbol[>..]&, relocations: Relocation[>..]&) -> Header, bool, u8[>..] {
    fn fail(what: const u8[:]) {
        return empty_header(), false, str("gobjtool: ", what) from parse;
    }

    if data.len < ELF_HEADER_SIZE { fail("truncated ELF header"); }
    if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
        fail("not an ELF file");
    }
    if data[4] != ELFCLASS64 { fail("only ELF64 objects are supported"); }
    if data[5] != ELFDATA2LSB { fail("only little-endian ELF objects are supported"); }
    if data[6] != EV_CURRENT as u8 { fail("unsupported ELF identification version"); }

    let file_type, type_ok = read_u16(data, 16);
    let machine, machine_ok = read_u16(data, 18);
    let version, version_ok = read_u32(data, 20);
    let entry, entry_ok = read_u64(data, 24);
    let program_offset, phoff_ok = read_u64(data, 32);
    let section_offset, shoff_ok = read_u64(data, 40);
    let flags, flags_ok = read_u32(data, 48);
    let header_size, ehsize_ok = read_u16(data, 52);
    let program_entry_size, phentsize_ok = read_u16(data, 54);
    let program_count, phnum_ok = read_u16(data, 56);
    let section_entry_size, shentsize_ok = read_u16(data, 58);
    let raw_section_count, shnum_ok = read_u16(data, 60);
    let raw_name_index, shstr_ok = read_u16(data, 62);
    if !type_ok || !machine_ok || !version_ok || !entry_ok || !phoff_ok ||
            !shoff_ok || !flags_ok || !ehsize_ok || !phentsize_ok || !phnum_ok ||
            !shentsize_ok || !shnum_ok || !shstr_ok {
        fail("truncated ELF header");
    }
    if file_type != ET_REL { fail("expected an ELF relocatable object"); }
    if machine != EM_X86_64 { fail("expected an x86-64 ELF object"); }
    if version != EV_CURRENT { fail("unsupported ELF version"); }
    if header_size != ELF_HEADER_SIZE { fail("invalid ELF header size"); }
    if section_entry_size != ELF_SECTION_SIZE {
        fail("invalid ELF section-header size");
    }
    if section_offset == 0 { fail("ELF object has no section table"); }

    let section_zero, zero_ok = read_section(data, section_offset,
                                             section_entry_size, 0);
    if !zero_ok { fail("truncated ELF section table"); }
    var count = raw_section_count as u64;
    if raw_section_count == 0 { count = section_zero.size; }
    if count == 0 || count > 0x7fffffffffffffff {
        fail("invalid ELF section count");
    }
    let table_size, table_size_ok = product(count, section_entry_size);
    if !table_size_ok || !range_ok(data, section_offset, table_size) {
        fail("truncated ELF section table");
    }

    var name_index = raw_name_index as u64;
    if raw_name_index == SHN_XINDEX { name_index = section_zero.link; }
    if name_index >= count { fail("invalid section-name string table index"); }

    for index in count as! i64 {
        let section, ok = read_section(data, section_offset,
                                       section_entry_size, index);
        if !ok { fail(str("cannot read section ", index)); }
        if section.kind != SHT_NOBITS && !range_ok(data, section.offset, section.size) {
            fail(str("section ", index, " lies outside the file"));
        }
        if section.align != 0 && (section.align & (section.align - 1)) != 0 {
            fail(str("section ", index, " has invalid alignment"));
        }
        sections.push(section);
    }

    let section_names = sections[name_index as! i64];
    for &section in sections {
        let section_name, ok = string_at(data, section_names, section.name_offset);
        if !ok { fail(str("invalid name for section ", section.index)); }
        section.name = section_name;
    }

    for table in sections {
        if table.kind != SHT_SYMTAB && table.kind != SHT_DYNSYM { continue; }
        if table.entry_size != ELF_SYMBOL_SIZE ||
                table.size % table.entry_size != 0 {
            fail(str("invalid symbol table entry size in section ", table.index));
        }
        if table.link >= sections.len {
            fail(str("invalid string-table link in section ", table.index));
        }
        let strings = sections[table.link as i64];
        if strings.kind != SHT_STRTAB {
            fail(str("symbol table ", table.index, " does not link to a string table"));
        }
        let count_symbols = table.size / table.entry_size;
        for symbol_index in count_symbols as! i64 {
            let at = table.offset + symbol_index as u64 * table.entry_size;
            let name_offset, name_ok = read_u32(data, at as! i64);
            let raw_section_index, section_ok = read_u16(data, at as! i64 + 6);
            let value, value_ok = read_u64(data, at as! i64 + 8);
            let size, size_ok = read_u64(data, at as! i64 + 16);
            if !name_ok || !section_ok || !value_ok || !size_ok {
                fail(str("truncated symbol ", symbol_index, " in section ", table.index));
            }
            let symbol_name, string_ok = string_at(data, strings, name_offset);
            if !string_ok {
                fail(str("invalid name for symbol ", symbol_index,
                         " in section ", table.index));
            }
            let full_section, full_ok = full_symbol_section(data, sections,
                table.index, symbol_index, raw_section_index);
            if !full_ok {
                fail(str("invalid extended section index for symbol ", symbol_index));
            }
            symbols.push(Symbol {
                table_section: table.index,
                index: symbol_index,
                name_offset: name_offset,
                info: data[at as! i64 + 4],
                other: data[at as! i64 + 5],
                section_index: full_section,
                value: value,
                size: size,
                name: symbol_name,
            });
        }
    }

    for table in sections {
        if table.kind != SHT_RELA && table.kind != SHT_REL { continue; }
        let expected_size = if table.kind == SHT_RELA {
            ELF_RELA_SIZE as u64
        } else {
            ELF_REL_SIZE as u64
        };
        if table.entry_size != expected_size || table.size % table.entry_size != 0 {
            fail(str("invalid relocation entry size in section ", table.index));
        }
        let linked_symbols, linked_ok = symbol_count(sections, table.link);
        if !linked_ok {
            fail(str("invalid symbol-table link in relocation section ", table.index));
        }
        if table.info >= sections.len {
            fail(str("invalid target link in relocation section ", table.index));
        }
        let count_relocations = table.size / table.entry_size;
        for relocation_index in count_relocations as! i64 {
            let at = table.offset + relocation_index as u64 * table.entry_size;
            let offset, offset_ok = read_u64(data, at as! i64);
            let info, info_ok = read_u64(data, at as! i64 + 8);
            if !offset_ok || !info_ok {
                fail(str("truncated relocation ", relocation_index,
                         " in section ", table.index));
            }
            let symbol_index = (info >> 32) as! u32;
            if symbol_index >= linked_symbols {
                fail(str("invalid symbol index in relocation ", relocation_index,
                         " of section ", table.index));
            }
            var addend: i64 = 0;
            if table.kind == SHT_RELA {
                let raw_addend, addend_ok = read_u64(data, at as! i64 + 16);
                if !addend_ok {
                    fail(str("truncated relocation addend in section ", table.index));
                }
                addend = raw_addend as! i64;
            }
            relocations.push(Relocation {
                relocation_section: table.index,
                index: relocation_index,
                target_section: table.info,
                symbol_table: table.link,
                offset: offset,
                symbol_index: symbol_index,
                kind: info as! u32,
                addend: addend,
                has_addend: table.kind == SHT_RELA,
            });
        }
    }

    return Header {
        file_type: file_type,
        machine: machine,
        version: version,
        entry: entry,
        program_offset: program_offset,
        section_offset: section_offset,
        flags: flags,
        program_entry_size: program_entry_size,
        program_count: program_count,
        section_count: count as! i64,
        section_name_index: name_index as! i64,
    }, true, [];
}

fn section_kind_name(kind: u32) -> const u8[:] {
    if kind == SHT_NULL { return "NULL"; }
    if kind == SHT_SYMTAB { return "SYMTAB"; }
    if kind == SHT_STRTAB { return "STRTAB"; }
    if kind == SHT_RELA { return "RELA"; }
    if kind == SHT_NOBITS { return "NOBITS"; }
    if kind == SHT_REL { return "REL"; }
    if kind == SHT_DYNSYM { return "DYNSYM"; }
    if kind == SHT_SYMTAB_SHNDX { return "SYMTAB_SHNDX"; }
    return "OTHER";
}
