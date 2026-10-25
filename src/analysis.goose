// SPDX-License-Identifier: GPL-2.0-or-later
//
// Decode executable sections into the persistent objtool model and build the
// first native CFG: linear fall-through, direct branches, and calls.  Linux
// alternatives, exception fixups, jump tables, and symbol-aware call targets
// are layered onto this graph in later passes.
namespace analysis;
import std;
import .elf;
import .model;
import .x86;

struct Stats {
    instructions: i64,
    edges: i64,
    stack_operations: i64,
    executable_sections: i64,
}

fn instruction_kind(kind: x86::Kind) -> model::InstructionKind {
    match kind {
        Other => model::InstructionKind.Other,
        Call => model::InstructionKind.Call,
        CallDynamic => model::InstructionKind.CallDynamic,
        Return => model::InstructionKind.Return,
        JumpConditional => model::InstructionKind.JumpConditional,
        JumpUnconditional => model::InstructionKind.JumpUnconditional,
        JumpDynamic => model::InstructionKind.JumpDynamic,
        Syscall => model::InstructionKind.Syscall,
        Sysret => model::InstructionKind.Sysret,
        Bug => model::InstructionKind.Bug,
        Nop => model::InstructionKind.Nop,
        Trap => model::InstructionKind.Trap,
        Endbr => model::InstructionKind.Endbr,
        Clac => model::InstructionKind.Clac,
        Stac => model::InstructionKind.Stac,
        Cld => model::InstructionKind.Cld,
        Std => model::InstructionKind.Std,
        LeaRip => model::InstructionKind.LeaRip,
    }
}

fn register(number: u8) -> model::X86Register, bool {
    if number == 0 { return model::X86Register.Ax, true; }
    if number == 1 { return model::X86Register.Cx, true; }
    if number == 2 { return model::X86Register.Dx, true; }
    if number == 3 { return model::X86Register.Bx, true; }
    if number == 4 { return model::X86Register.Sp, true; }
    if number == 5 { return model::X86Register.Bp, true; }
    if number == 6 { return model::X86Register.Si, true; }
    if number == 7 { return model::X86Register.Di, true; }
    if number == 8 { return model::X86Register.R8, true; }
    if number == 9 { return model::X86Register.R9, true; }
    if number == 10 { return model::X86Register.R10, true; }
    if number == 11 { return model::X86Register.R11, true; }
    if number == 12 { return model::X86Register.R12, true; }
    if number == 13 { return model::X86Register.R13, true; }
    if number == 14 { return model::X86Register.R14, true; }
    if number == 15 { return model::X86Register.R15, true; }
    return model::X86Register.Ax, false;
}

fn rex_w(d: x86::Decoded) -> bool { d.rex_count != 0 && d.rex0 & 8 != 0 }
fn rex_r(d: x86::Decoded) -> u8 {
    if d.rex_count == 0 { return 0; }
    return (d.rex0 >> 2) & 1;
}
fn rex_x(d: x86::Decoded) -> u8 {
    if d.rex_count == 0 { return 0; }
    return (d.rex0 >> 1) & 1;
}
fn rex_b(d: x86::Decoded) -> u8 {
    if d.rex_count == 0 { return 0; }
    return d.rex0 & 1;
}
fn modrm_mod(d: x86::Decoded) -> u8 { d.modrm >> 6 }
fn modrm_register(d: x86::Decoded) -> u8 {
    ((d.modrm >> 3) & 7) + 8 * rex_r(d)
}
fn modrm_rm(d: x86::Decoded) -> u8 { (d.modrm & 7) + 8 * rex_b(d) }
fn has_sib(d: x86::Decoded) -> bool {
    d.has_modrm && modrm_mod(d) != 3 && (modrm_rm(d) & 7) == 4
}
fn is_rip(d: x86::Decoded) -> bool {
    d.has_modrm && modrm_mod(d) == 0 && (modrm_rm(d) & 7) == 5
}
fn sib_index(d: x86::Decoded) -> u8 { ((d.sib >> 3) & 7) + 8 * rex_x(d) }
fn sib_base(d: x86::Decoded) -> u8 { (d.sib & 7) + 8 * rex_b(d) }
fn rm_is(d: x86::Decoded, wanted: u8) -> bool {
    if has_sib(d) {
        let base = sib_base(d);
        return base == wanted && sib_index(d) == 4 &&
               (base != 5 || modrm_mod(d) != 0);
    }
    return modrm_rm(d) == wanted;
}
fn rm_is_memory(d: x86::Decoded, wanted: u8) -> bool {
    modrm_mod(d) != 3 && !is_rip(d) && rm_is(d, wanted)
}
fn rm_is_register(d: x86::Decoded, wanted: u8) -> bool {
    modrm_mod(d) == 3 && modrm_rm(d) == wanted
}

fn add_register_push(owner: model::InstructionId, number: u8) {
    let source, ok = register(number);
    if !ok { return; }
    model::add_stack_operation(
        owner, model::StackDestination.Push,
        model::StackSource.Register { register: source });
}

fn add_register_pop(owner: model::InstructionId, number: u8) {
    let destination, ok = register(number);
    if !ok { return; }
    model::add_stack_operation(
        owner,
        model::StackDestination.Register { register: destination },
        model::StackSource.Pop);
}

fn add_stack_operations(owner: model::InstructionId, d: x86::Decoded) {
    if d.vex_count != 0 { return; }
    let opcode = d.opcode0;
    let displacement = d.displacement as! i32;

    if opcode == 0x01 || opcode == 0x29 {
        if rex_w(d) && rm_is_register(d, 4) {
            let source, ok = register(modrm_register(d));
            if ok {
                model::add_stack_operation(
                    owner,
                    model::StackDestination.Register {
                        register: model::X86Register.Sp,
                    },
                    model::StackSource.Add { register: source, value: 0 });
            }
        }
        return;
    }
    if opcode >= 0x50 && opcode <= 0x57 {
        add_register_push(owner, (opcode & 7) + 8 * rex_b(d));
        return;
    }
    if opcode >= 0x58 && opcode <= 0x5f {
        add_register_pop(owner, (opcode & 7) + 8 * rex_b(d));
        return;
    }
    if opcode == 0x68 || opcode == 0x6a {
        model::add_stack_operation(
            owner, model::StackDestination.Push,
            model::StackSource.Constant { value: 0 });
        return;
    }
    if opcode >= 0x80 && opcode <= 0x83 && rex_w(d) &&
       rm_is_register(d, 4) {
        let operation = modrm_register(d) & 7;
        if operation == 0 || operation == 5 {
            let amount = if operation == 5 { 0 - d.immediate } else { d.immediate };
            model::add_stack_operation(
                owner,
                model::StackDestination.Register {
                    register: model::X86Register.Sp,
                },
                model::StackSource.Add {
                    register: model::X86Register.Sp,
                    value: amount as! i32,
                });
        } else if operation == 4 {
            model::add_stack_operation(
                owner,
                model::StackDestination.Register {
                    register: model::X86Register.Sp,
                },
                model::StackSource.And {
                    register: model::X86Register.Sp,
                    value: d.immediate as! i32,
                });
        }
        return;
    }
    if opcode == 0x89 && rex_w(d) {
        let source, source_ok = register(modrm_register(d));
        if modrm_mod(d) == 3 {
            let destination, destination_ok = register(modrm_rm(d));
            if source_ok && destination_ok {
                model::add_stack_operation(
                    owner,
                    model::StackDestination.Register { register: destination },
                    model::StackSource.Register { register: source });
            }
            return;
        }
        if is_rip(d) { return; }
        var base_number = modrm_rm(d);
        if has_sib(d) {
            base_number = sib_base(d);
            if sib_index(d) != 4 { return; }
        }
        let base, base_ok = register(base_number);
        if modrm_register(d) == 4 && base_ok {
            model::add_stack_operation(
                owner,
                model::StackDestination.RegisterIndirect {
                    register: base, offset: displacement,
                },
                model::StackSource.Register { register: model::X86Register.Sp });
            return;
        }
        if source_ok && base_ok && (base_number == 4 || base_number == 5) {
            model::add_stack_operation(
                owner,
                model::StackDestination.RegisterIndirect {
                    register: base, offset: displacement,
                },
                model::StackSource.Register { register: source });
        }
        return;
    }
    if opcode == 0x88 && rex_w(d) {
        let source, source_ok = register(modrm_register(d));
        if source_ok && (rm_is_memory(d, 4) || rm_is_memory(d, 5)) {
            let base, base_ok = register(if rm_is_memory(d, 4) { 4 } else { 5 });
            if base_ok {
                model::add_stack_operation(
                    owner,
                    model::StackDestination.RegisterIndirect {
                        register: base, offset: displacement,
                    },
                    model::StackSource.Register { register: source });
            }
        }
        return;
    }
    if opcode == 0x8b && rex_w(d) {
        let destination, destination_ok = register(modrm_register(d));
        if destination_ok && (rm_is_memory(d, 4) || rm_is_memory(d, 5)) {
            let base, base_ok = register(if rm_is_memory(d, 4) { 4 } else { 5 });
            if base_ok {
                model::add_stack_operation(
                    owner,
                    model::StackDestination.Register { register: destination },
                    model::StackSource.RegisterIndirect {
                        register: base, offset: displacement,
                    });
            }
        }
        return;
    }
    if opcode == 0x8d && rex_w(d) && modrm_mod(d) != 3 && !is_rip(d) {
        var source_number = modrm_rm(d);
        if has_sib(d) {
            source_number = sib_base(d);
            if sib_index(d) != 4 { return; }
        }
        let source, source_ok = register(source_number);
        let destination, destination_ok = register(modrm_register(d));
        if source_ok && destination_ok {
            let source_value: model::StackSource = if displacement == 0 {
                model::StackSource.Register { register: source }
            } else {
                model::StackSource.Add { register: source, value: displacement }
            };
            model::add_stack_operation(
                owner,
                model::StackDestination.Register { register: destination },
                source_value);
        }
        return;
    }
    if opcode == 0x8f {
        model::add_stack_operation(
            owner, model::StackDestination.Memory, model::StackSource.Pop);
        return;
    }
    if opcode == 0x9c {
        model::add_stack_operation(
            owner, model::StackDestination.PushFlags,
            model::StackSource.Constant { value: 0 });
        return;
    }
    if opcode == 0x9d {
        model::add_stack_operation(
            owner, model::StackDestination.Memory, model::StackSource.PopFlags);
        return;
    }
    if opcode == 0x0f && (d.opcode1 == 0xa0 || d.opcode1 == 0xa8) {
        model::add_stack_operation(
            owner, model::StackDestination.Push,
            model::StackSource.Constant { value: 0 });
        return;
    }
    if opcode == 0x0f && (d.opcode1 == 0xa1 || d.opcode1 == 0xa9) {
        model::add_stack_operation(
            owner, model::StackDestination.Memory, model::StackSource.Pop);
        return;
    }
    if opcode == 0xc9 {
        model::add_stack_operation(
            owner,
            model::StackDestination.Register { register: model::X86Register.Sp },
            model::StackSource.Register { register: model::X86Register.Bp });
        model::add_stack_operation(
            owner,
            model::StackDestination.Register { register: model::X86Register.Bp },
            model::StackSource.Pop);
        return;
    }
    if opcode == 0xe8 {
        model::add_stack_operation(
            owner, model::StackDestination.Push,
            model::StackSource.Constant { value: 0 });
        return;
    }
    if opcode == 0xff && modrm_register(d) == 6 {
        model::add_stack_operation(
            owner, model::StackDestination.Push,
            model::StackSource.Constant { value: 0 });
    }
}

fn find_instruction(section_index: u32, offset: u64) -> model::InstructionId, bool {
    var low = 0;
    var high = model::instruction_pool.len;
    while low < high {
        let middle = low + (high - low) / 2;
        let instruction = model::instruction_pool[middle];
        if instruction.section_index < section_index ||
           (instruction.section_index == section_index && instruction.offset < offset) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }
    if low < model::instruction_pool.len {
        let instruction = model::instruction_pool[low];
        if instruction.section_index == section_index && instruction.offset == offset {
            return low as model::InstructionId, true;
        }
    }
    return 0 as model::InstructionId, false;
}

fn branch_target(offset: u64, length: u8, displacement: i64) -> u64, bool {
    let instruction_length: u64 = length;
    if offset > 0xffffffffffffffff - instruction_length { return 0, false; }
    let base = offset + instruction_length;
    if displacement >= 0 {
        let add = displacement as u64;
        if base > 0xffffffffffffffff - add { return 0, false; }
        return base + add, true;
    }
    let subtract = (0 - displacement) as u64;
    if base < subtract { return 0, false; }
    return base - subtract, true;
}

fn has_immediate_relocation(relocations: elf::Relocation[:],
                            instruction: model::Instruction) -> bool {
    if instruction.immediate_length == 0 { return false; }
    let begin = instruction.offset + instruction.length - instruction.immediate_length;
    let end = begin + instruction.immediate_length;
    for relocation in relocations {
        if relocation.target_section == instruction.section_index &&
           relocation.offset >= begin && relocation.offset < end {
            return true;
        }
    }
    return false;
}

fn add_target_edge(source: model::InstructionId, kind: model::CfgEdgeKind,
                   relocations: elf::Relocation[:]) {
    let instruction = model::instruction_pool[source];
    if has_immediate_relocation(relocations, instruction) {
        model::add_unresolved_cfg_edge(source, kind);
        return;
    }
    let target_offset, target_ok = branch_target(
        instruction.offset, instruction.length, instruction.immediate as! i64);
    if target_ok {
        let target, found = find_instruction(instruction.section_index, target_offset);
        if found {
            model::add_cfg_edge(source, target, kind);
            return;
        }
    }
    model::add_unresolved_cfg_edge(source, kind);
}

fn can_fall_through(kind: model::InstructionKind) -> bool {
    match kind {
        JumpUnconditional => false,
        JumpDynamic => false,
        Return => false,
        Sysret => false,
        Bug => false,
        _ => true,
    }
}

fn build_edges(relocations: elf::Relocation[:]) {
    let count = model::instruction_pool.len;
    for raw_index in count {
        let source = raw_index as model::InstructionId;
        let instruction = model::instruction_pool[source];
        match instruction.kind {
            JumpConditional => add_target_edge(
                source, model::CfgEdgeKind.DirectJump, relocations),
            JumpUnconditional => add_target_edge(
                source, model::CfgEdgeKind.DirectJump, relocations),
            JumpDynamic => model::add_unresolved_cfg_edge(
                source, model::CfgEdgeKind.IndirectJump),
            JumpDynamicConditional => model::add_unresolved_cfg_edge(
                source, model::CfgEdgeKind.IndirectJump),
            Call => add_target_edge(source, model::CfgEdgeKind.Call, relocations),
            CallDynamic => model::add_unresolved_cfg_edge(
                source, model::CfgEdgeKind.Call),
            _ => {},
        }
        if can_fall_through(instruction.kind) && raw_index + 1 < count {
            let next = (raw_index + 1) as model::InstructionId;
            if model::instruction_pool[next].section_index == instruction.section_index {
                model::add_cfg_edge(source, next, model::CfgEdgeKind.Fallthrough);
            }
        }
    }
}

fn build(data: const u8[:], sections: elf::Section[:],
         relocations: elf::Relocation[:], verbose: bool) -> Stats, bool, u8[>..] {
    var stats = Stats {
        instructions: 0,
        edges: 0,
        stack_operations: 0,
        executable_sections: 0,
    };
    var failure: u8[>..] = [];
    var previous_length: u8 = 0;
    for section in sections {
        if section.flags & 4 == 0 || section.size == 0 { continue; }
        stats.executable_sections += 1;
        previous_length = 0;
        let begin = section.offset;
        let size = section.size;
        if begin > data.len as u64 || size > data.len as u64 - begin {
            format(failure, "executable section outside file: ", section.name);
            return stats, false, failure;
        }
        let bytes = data[(begin as! i64)..((begin + size) as! i64)];
        var offset = 0;
        while offset < bytes.len {
            let decoded, ok, error = x86::decode(bytes, offset);
            if !ok {
                format(failure, "can't decode instruction at ", section.name,
                       "+", offset, ": ", error);
                return stats, false, failure;
            }
            let id = model::add_instruction(
                section.index as! u32, offset as u64, decoded.length,
                instruction_kind(x86::classify(decoded)));
            model::instruction_pool[id].previous_length = previous_length;
            model::instruction_pool[id].immediate = decoded.immediate as! u64;
            model::instruction_pool[id].immediate_length = decoded.immediate_size;
            if model::instruction_pool[id].kind == model::InstructionKind.Bug {
                model::instruction_pool[id].flags.dead_end = true;
            }
            add_stack_operations(id, decoded);
            if verbose {
                print("instruction section=", section.name,
                      " offset=", offset,
                      " length=", decoded.length,
                      " kind=", x86::kind_name(x86::classify(decoded)),
                      " immediate=", decoded.immediate,
                      " immediate-size=", decoded.immediate_size,
                      " displacement=", decoded.displacement,
                      " displacement-size=", decoded.displacement_size);
            }
            previous_length = decoded.length;
            offset += decoded.length;
        }
    }
    build_edges(relocations);
    stats.instructions = model::instruction_pool.len;
    stats.edges = model::cfg_edge_pool.len;
    stats.stack_operations = model::stack_op_pool.len;
    return stats, true, failure;
}
