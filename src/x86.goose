// SPDX-License-Identifier: GPL-2.0-or-later
//
// Native x86-64 instruction decoding for gobjtool.  The length decoder is a
// checked Goose port of Linux arch/x86/lib/{inat,insn}.c.  Its generated
// attributes come from the same Linux x86 opcode map as upstream objtool.
namespace x86;
import .x86_tables;

let MAX_INSN_SIZE = 15;

let PFX_MASK: u32 = 0x1f;
let ESC_MASK: u32 = 0x60;
let GRP_MASK: u32 = 0x0f80;
let IMM_MASK: u32 = 0x7000;
let MODRM: u32 = 1 << 15;
let FORCE64: u32 = 1 << 16;
let SCNDIMM: u32 = 1 << 17;
let MOFFSET: u32 = 1 << 18;
let VARIANT: u32 = 1 << 19;
let VEXOK: u32 = 1 << 20;
let VEXONLY: u32 = 1 << 21;
let EVEXONLY: u32 = 1 << 22;
let EVEX_SCALABLE: u32 = 1 << 25;
let INV64: u32 = 1 << 26;

let PFX_OPNDSZ: u8 = 1;
let PFX_REPE: u8 = 2;
let PFX_REPNE: u8 = 3;
let PFX_ADDRSZ: u8 = 11;
let PFX_REX: u8 = 12;
let PFX_VEX2: u8 = 13;
let PFX_VEX3: u8 = 14;
let PFX_EVEX: u8 = 15;
let PFX_REX2: u8 = 16;
let PFX_XOP: u8 = 17;

let IMM_BYTE: u8 = 1;
let IMM_WORD: u8 = 2;
let IMM_DWORD: u8 = 3;
let IMM_QWORD: u8 = 4;
let IMM_PTR: u8 = 5;
let IMM_VWORD32: u8 = 6;
let IMM_VWORD: u8 = 7;

enum Kind {
    Other,
    Call,
    CallDynamic,
    Return,
    JumpConditional,
    JumpUnconditional,
    JumpDynamic,
    Syscall,
    Sysret,
    Bug,
    Nop,
    Trap,
    Endbr,
    Clac,
    Stac,
    Cld,
    Std,
    LeaRip,
}

struct Decoded {
    length: u8,
    operand_bytes: u8,
    address_bytes: u8,
    emulate_prefix_size: u8,
    prefix_count: u8,
    prefix0: u8,
    last_prefix: u8,
    has_notrack: bool,
    rex_count: u8,
    rex0: u8,
    rex1: u8,
    vex_count: u8,
    vex0: u8,
    vex1: u8,
    vex2: u8,
    vex3: u8,
    opcode_count: u8,
    opcode0: u8,
    opcode1: u8,
    opcode2: u8,
    attr: u32,
    has_modrm: bool,
    modrm: u8,
    has_sib: bool,
    sib: u8,
    displacement_offset: u8,
    displacement_size: u8,
    displacement: i64,
    immediate_offset: u8,
    immediate_size: u8,
    immediate: i64,
    second_immediate_size: u8,
}

fn empty() -> Decoded {
    Decoded {
        length: 0,
        operand_bytes: 4,
        address_bytes: 8,
        emulate_prefix_size: 0,
        prefix_count: 0,
        prefix0: 0,
        last_prefix: 0,
        has_notrack: false,
        rex_count: 0,
        rex0: 0,
        rex1: 0,
        vex_count: 0,
        vex0: 0,
        vex1: 0,
        vex2: 0,
        vex3: 0,
        opcode_count: 0,
        opcode0: 0,
        opcode1: 0,
        opcode2: 0,
        attr: 0,
        has_modrm: false,
        modrm: 0,
        has_sib: false,
        sib: 0,
        displacement_offset: 0,
        displacement_size: 0,
        displacement: 0,
        immediate_offset: 0,
        immediate_size: 0,
        immediate: 0,
        second_immediate_size: 0,
    }
}

fn prefix_id(attr: u32) -> u8 { (attr & PFX_MASK) as! u8 }
fn is_legacy_prefix(attr: u32) -> bool {
    let p = prefix_id(attr);
    p != 0 && p <= PFX_ADDRSZ
}
fn is_vex_prefix(attr: u32) -> bool {
    let p = prefix_id(attr);
    p == PFX_VEX2 || p == PFX_VEX3 || p == PFX_EVEX
}
fn last_prefix_id(last: u8, d: Decoded) -> u8 {
    if d.vex_count != 0 {
        if prefix_id(x86_tables::primary(d.vex0)) == PFX_XOP {
            return d.vex2 & 3;
        }
        if d.vex_count == 2 { return d.vex1 & 3; }
        return d.vex2 & 3;
    }
    let p = prefix_id(x86_tables::primary(last));
    if p <= PFX_REPNE { return p; }
    return 0;
}

fn escape_attribute(opcode: u8, last: u8, escape_attr: u32) -> u32 {
    let escape = ((escape_attr & ESC_MASK) >> 5) as! u8;
    let base, ok = x86_tables::escape_raw(escape, 0, opcode);
    if !ok { return 0; }
    if base & VARIANT != 0 && last != 0 {
        let selected, selected_ok = x86_tables::escape_raw(escape, last, opcode);
        if !selected_ok { return 0; }
        return selected;
    }
    return base;
}

fn group_attribute(modrm: u8, last: u8, group_attr: u32) -> u32 {
    let group = ((group_attr & GRP_MASK) >> 7) as! u8;
    let common = group_attr & ~GRP_MASK;
    let register = (modrm >> 3) & 7;
    let base, ok = x86_tables::group_raw(group, 0, register);
    if !ok { return common; }
    if base & VARIANT != 0 && last != 0 {
        let selected, selected_ok = x86_tables::group_raw(group, last, register);
        if !selected_ok { return common; }
        return selected | common;
    }
    return base | common;
}

fn avx_attribute(opcode: u8, map: u8, prefix: u8) -> u32 {
    if map > 31 || prefix > 3 { return 0; }
    let base, ok = x86_tables::avx_raw(map, 0, opcode);
    if !ok { return 0; }
    if base & GRP_MASK == 0 && prefix != 0 {
        let selected, selected_ok = x86_tables::avx_raw(map, prefix, opcode);
        if !selected_ok { return 0; }
        return selected;
    }
    return base;
}

fn byte_at(data: const u8[:], at: i64, end: i64) -> u8, bool {
    if at < 0 || at >= end || at >= data.len { return 0, false; }
    return data[at], true;
}

fn take(data: const u8[:], at: i64&, end: i64) -> u8, bool {
    let b, ok = byte_at(data, at, end);
    if ok { at += 1; }
    return b, ok;
}

fn sequence_at(data: const u8[:], at: i64, end: i64,
               a: u8, b: u8, c: u8, d: u8, e: u8) -> bool {
    if at < 0 || end - at < 5 { return false; }
    data[at] == a && data[at + 1] == b && data[at + 2] == c &&
    data[at + 3] == d && data[at + 4] == e
}

fn read_signed(data: const u8[:], at: i64&, end: i64,
               size: u8) -> i64, bool {
    if size == 0 || size > 8 || at < 0 || size > (end - at) as u8 {
        return 0, false;
    }
    var raw: u64 = 0;
    for i in size as i64 {
        raw |= (data[at + i] as u64) << ((i * 8) as u8);
    }
    at += size;
    if size == 8 { return raw as! i64, true; }
    let bits = size * 8;
    let sign: u64 = 1 << (bits - 1);
    if raw & sign != 0 {
        return (raw as i64) - (1 << bits), true;
    }
    return raw as i64, true;
}

fn decode(data: const u8[:], start: i64) -> Decoded, bool, const u8[:] {
    var d = empty();
    if start < 0 || start >= data.len {
        return d, false, "instruction starts outside input";
    }
    let available = data.len - start;
    let limit = if available < MAX_INSN_SIZE { available } else { MAX_INSN_SIZE };
    let end = start + limit;
    var at = start;

    if sequence_at(data, at, end, 0x0f, 0x0b, 0x78, 0x65, 0x6e) ||
       sequence_at(data, at, end, 0x0f, 0x0b, 0x6b, 0x76, 0x6d) {
        d.emulate_prefix_size = 5;
        at += 5;
    }

    var unique: u8[4] = [0; 4];
    var unique_count: u8 = 0;
    var last: u8 = 0;
    loop {
        let b, ok = byte_at(data, at, end);
        if !ok { return d, false, "truncated x86 prefix or opcode"; }
        let attr = x86_tables::primary(b);
        if !is_legacy_prefix(attr) { break; }
        var seen = false;
        for i in unique_count as i64 {
            if unique[i] == b { seen = true; }
        }
        if !seen {
            if unique_count == 4 { break; }
            unique[unique_count as i64] = b;
            unique_count += 1;
            let p = prefix_id(attr);
            if p == PFX_ADDRSZ { d.address_bytes ^= 12; }
            else if p == PFX_OPNDSZ { d.operand_bytes ^= 6; }
        }
        if b == 0x3e { d.has_notrack = true; }
        d.prefix_count += 1;
        at += 1;
        last = b;
    }
    if unique_count != 0 {
        if last != unique[3] {
            if unique[3] != 0 {
                for i in unique_count as i64 {
                    if unique[i] == last { unique[i] = unique[3]; }
                }
            }
            unique[3] = last;
        }
        d.prefix0 = unique[0];
        d.last_prefix = unique[3];
    }

    let before_rex, before_rex_ok = byte_at(data, at, end);
    if !before_rex_ok { return d, false, "truncated x86 opcode"; }
    let before_rex_attr = x86_tables::primary(before_rex);
    var skip_vex = false;
    if prefix_id(before_rex_attr) == PFX_REX {
        d.rex0 = before_rex;
        d.rex_count = 1;
        at += 1;
        if before_rex & 8 != 0 { d.operand_bytes = 8; }
    } else if prefix_id(before_rex_attr) == PFX_REX2 {
        let first, first_ok = take(data, at, end);
        let second, second_ok = take(data, at, end);
        if !first_ok || !second_ok { return d, false, "truncated REX2 prefix"; }
        d.rex0 = first;
        d.rex1 = second;
        d.rex_count = 2;
        if second & 8 != 0 { d.operand_bytes = 8; }
        skip_vex = true;
    }

    if !skip_vex {
        let lead, lead_ok = byte_at(data, at, end);
        if !lead_ok { return d, false, "truncated x86 opcode"; }
        let lead_attr = if d.rex_count == 0 { before_rex_attr }
                        else { x86_tables::primary(d.rex0) };
        if is_vex_prefix(lead_attr) || prefix_id(lead_attr) == PFX_XOP {
            let second, second_ok = byte_at(data, at + 1, end);
            if !second_ok { return d, false, "truncated VEX/XOP prefix"; }
            if !(prefix_id(lead_attr) == PFX_XOP && ((second >> 3) & 7) == 0) {
                d.vex0 = lead;
                d.vex1 = second;
                if prefix_id(lead_attr) == PFX_EVEX {
                    let third, third_ok = byte_at(data, at + 2, end);
                    let fourth, fourth_ok = byte_at(data, at + 3, end);
                    if !third_ok || !fourth_ok {
                        return d, false, "truncated EVEX prefix";
                    }
                    d.vex2 = third;
                    d.vex3 = fourth;
                    d.vex_count = 4;
                    at += 4;
                    if fourth & 0x80 != 0 { d.operand_bytes = 8; }
                } else if prefix_id(lead_attr) == PFX_VEX3 ||
                          prefix_id(lead_attr) == PFX_XOP {
                    let third, third_ok = byte_at(data, at + 2, end);
                    if !third_ok { return d, false, "truncated VEX3/XOP prefix"; }
                    d.vex2 = third;
                    d.vex_count = 3;
                    at += 3;
                    if third & 0x80 != 0 { d.operand_bytes = 8; }
                } else {
                    d.vex2 = second & 0x7f;
                    d.vex_count = 2;
                    at += 2;
                }
            }
        }
    }

    let opcode, opcode_ok = take(data, at, end);
    if !opcode_ok { return d, false, "truncated x86 opcode"; }
    d.opcode0 = opcode;
    d.opcode_count = 1;

    if d.vex_count != 0 {
        if prefix_id(x86_tables::primary(d.vex0)) == PFX_XOP {
            let map = d.vex1 & 0x1f;
            let attr, ok = x86_tables::xop_raw(map, opcode);
            if !ok || attr & VEXOK == 0 {
                return d, false, "invalid XOP instruction";
            }
            d.attr = attr;
        } else {
            let map = if d.vex_count == 2 { 1 }
                      else if d.vex_count == 3 { d.vex1 & 0x1f }
                      else { d.vex1 & 7 };
            let p = if d.vex_count == 2 { d.vex1 & 3 } else { d.vex2 & 3 };
            d.attr = avx_attribute(opcode, map, p);
            if d.attr & EVEX_SCALABLE != 0 && d.vex2 & 0x80 == 0 &&
               p == PFX_OPNDSZ {
                d.operand_bytes = 2;
            }
            if (d.attr & EVEXONLY != 0 && d.vex_count != 4) ||
               (d.attr & VEXOK == 0 && d.attr & GRP_MASK == 0) {
                return d, false, "invalid VEX/EVEX instruction";
            }
        }
    } else if d.rex_count == 2 {
        if d.rex1 & 0x80 != 0 {
            let escape = x86_tables::primary(0x0f);
            d.attr = escape_attribute(opcode, last_prefix_id(d.last_prefix, d), escape);
        } else {
            d.attr = x86_tables::primary(opcode);
        }
    } else {
        d.attr = x86_tables::primary(opcode);
        if d.attr & INV64 != 0 { d.attr &= INV64; }
        while d.attr & ESC_MASK != 0 {
            let escaped, escaped_ok = take(data, at, end);
            if !escaped_ok { return d, false, "truncated escaped opcode"; }
            if d.opcode_count == 1 { d.opcode1 = escaped; }
            else if d.opcode_count == 2 { d.opcode2 = escaped; }
            else { return d, false, "x86 opcode has too many escape bytes"; }
            d.opcode_count += 1;
            d.attr = escape_attribute(
                escaped, last_prefix_id(d.last_prefix, d), d.attr);
        }
        if d.attr & (VEXONLY | EVEXONLY) != 0 {
            return d, false, "VEX-only opcode used without VEX";
        }
    }

    if d.attr & MODRM != 0 {
        let modrm, modrm_ok = take(data, at, end);
        if !modrm_ok { return d, false, "truncated ModRM byte"; }
        d.modrm = modrm;
        d.has_modrm = true;
        if d.attr & GRP_MASK != 0 {
            d.attr = group_attribute(modrm, last_prefix_id(d.last_prefix, d), d.attr);
            if d.vex_count != 0 && d.attr & VEXOK == 0 {
                return d, false, "invalid VEX/XOP opcode group";
            }
        }
    }
    if d.attr & FORCE64 != 0 { d.operand_bytes = 8; }

    if d.has_modrm {
        let mod = d.modrm >> 6;
        let rm = d.modrm & 7;
        if d.address_bytes != 2 && mod != 3 && rm == 4 {
            let sib, sib_ok = take(data, at, end);
            if !sib_ok { return d, false, "truncated SIB byte"; }
            d.sib = sib;
            d.has_sib = true;
        }
    }

    d.displacement_offset = (at - start) as! u8;
    var displacement_size: u8 = 0;
    if d.has_modrm {
        let mod = d.modrm >> 6;
        let rm = d.modrm & 7;
        let base = if d.has_sib { d.sib & 7 } else { 0 };
        if mod == 1 { displacement_size = 1; }
        else if d.address_bytes == 2 {
            if (mod == 0 && rm == 6) || mod == 2 { displacement_size = 2; }
        } else if (mod == 0 && rm == 5) || mod == 2 ||
                  (mod == 0 && d.has_sib && base == 5) {
            displacement_size = 4;
        }
    }
    if displacement_size != 0 {
        let displacement, displacement_ok = read_signed(data, at, end, displacement_size);
        if !displacement_ok { return d, false, "truncated displacement"; }
        d.displacement = displacement;
        d.displacement_size = displacement_size;
    }

    d.immediate_offset = (at - start) as! u8;
    var immediate_size: u8 = 0;
    if d.attr & MOFFSET != 0 {
        immediate_size = d.address_bytes;
    } else if d.attr & IMM_MASK != 0 {
        let form = ((d.attr & IMM_MASK) >> 12) as! u8;
        if form == IMM_BYTE { immediate_size = 1; }
        else if form == IMM_WORD { immediate_size = 2; }
        else if form == IMM_DWORD { immediate_size = 4; }
        else if form == IMM_QWORD { immediate_size = 8; }
        else if form == IMM_PTR {
            if d.operand_bytes == 8 { return d, false, "invalid far-pointer immediate"; }
            immediate_size = d.operand_bytes + 2;
        } else if form == IMM_VWORD32 {
            immediate_size = if d.operand_bytes == 2 { 2 } else { 4 };
        } else if form == IMM_VWORD {
            immediate_size = d.operand_bytes;
        } else {
            return d, false, "invalid immediate-size attribute";
        }
    }
    if immediate_size != 0 {
        let immediate, immediate_ok = read_signed(data, at, end, immediate_size);
        if !immediate_ok { return d, false, "truncated immediate"; }
        d.immediate = immediate;
        d.immediate_size = immediate_size;
    }
    if d.attr & SCNDIMM != 0 {
        let ignored, second_ok = take(data, at, end);
        if !second_ok { return d, false, "truncated second immediate"; }
        d.second_immediate_size = 1;
    }

    d.length = (at - start) as! u8;
    if d.length == 0 || d.length > MAX_INSN_SIZE {
        return d, false, "invalid x86 instruction length";
    }
    return d, true, "";
}

fn rip_relative(d: Decoded) -> bool {
    d.has_modrm && (d.modrm & 0xc7) == 5
}

fn classify(d: Decoded) -> Kind {
    if d.vex_count != 0 { return Kind.Other; }
    let rex_b = d.rex_count != 0 && d.rex0 & 1 != 0;
    let rex_r: u8 = if d.rex_count != 0 { (d.rex0 >> 2) & 1 } else { 0 };
    let modrm_register = if d.has_modrm {
        ((d.modrm >> 3) & 7) + 8 * rex_r
    } else { 0 };

    if d.opcode0 >= 0x70 && d.opcode0 <= 0x7f { return Kind.JumpConditional; }
    if d.opcode0 >= 0xe0 && d.opcode0 <= 0xe3 { return Kind.JumpConditional; }
    if d.opcode0 == 0xe9 || d.opcode0 == 0xeb { return Kind.JumpUnconditional; }
    if d.opcode0 == 0xe8 { return Kind.Call; }
    if d.opcode0 == 0xc2 || d.opcode0 == 0xc3 { return Kind.Return; }
    if d.opcode0 == 0xca || d.opcode0 == 0xcb || d.opcode0 == 0xcf {
        return Kind.Sysret;
    }
    if d.opcode0 == 0xd6 { return Kind.Bug; }
    if d.opcode0 == 0xcc { return Kind.Trap; }
    if d.opcode0 == 0xfc { return Kind.Cld; }
    if d.opcode0 == 0xfd { return Kind.Std; }
    if d.opcode0 == 0x90 && !rex_b && d.prefix0 != 0xf3 { return Kind.Nop; }
    if d.opcode0 == 0x8d && d.rex0 & 8 != 0 && rip_relative(d) {
        return Kind.LeaRip;
    }
    if d.opcode0 == 0xff {
        if modrm_register == 2 || modrm_register == 3 { return Kind.CallDynamic; }
        if modrm_register == 4 { return Kind.JumpDynamic; }
        if modrm_register == 5 { return Kind.Sysret; }
    }
    if d.opcode0 == 0x0f {
        if d.opcode1 >= 0x80 && d.opcode1 <= 0x8f { return Kind.JumpConditional; }
        if d.opcode1 == 0x05 || d.opcode1 == 0x34 { return Kind.Syscall; }
        if d.opcode1 == 0x07 || d.opcode1 == 0x35 { return Kind.Sysret; }
        if d.opcode1 == 0x0b || d.opcode1 == 0xb9 { return Kind.Bug; }
        if d.opcode1 == 0x1f && modrm_register == 0 { return Kind.Nop; }
        if d.opcode1 == 0x1e && d.prefix0 == 0xf3 &&
           (d.modrm == 0xfa || d.modrm == 0xfb) { return Kind.Endbr; }
        if d.opcode1 == 0x01 {
            let p = last_prefix_id(d.last_prefix, d);
            if (p == PFX_REPE || p == PFX_REPNE) && d.modrm == 0xca {
                return Kind.Sysret;
            }
            if p == 0 && d.modrm == 0xca { return Kind.Clac; }
            if p == 0 && d.modrm == 0xcb { return Kind.Stac; }
        }
    }
    return Kind.Other;
}

fn kind_name(kind: Kind) -> const u8[:] {
    match kind {
        Other => "other",
        Call => "call",
        CallDynamic => "call-dynamic",
        Return => "return",
        JumpConditional => "jump-conditional",
        JumpUnconditional => "jump-unconditional",
        JumpDynamic => "jump-dynamic",
        Syscall => "syscall",
        Sysret => "sysret",
        Bug => "bug",
        Nop => "nop",
        Trap => "trap",
        Endbr => "endbr",
        Clac => "clac",
        Stac => "stac",
        Cld => "cld",
        Std => "std",
        LeaRip => "lea-rip",
    }
}
