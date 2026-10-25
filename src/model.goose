// SPDX-License-Identifier: GPL-2.0-or-later
//
// Stable, fixed-size data model shared by the x86 decoder and the objtool
// control-flow/stack validator.  All graph links are offsets into named
// grow-only pools: growing a pool cannot invalidate a live link, and a model
// contains no allocator-owned pointers.
namespace model;

// Keep this vocabulary aligned with tools/objtool/include/objtool/arch.h.
// Other is first so a default-initialized value is conservative rather than
// accidentally becoming a branch.
enum InstructionKind {
    Other,
    JumpConditional,
    JumpUnconditional,
    JumpDynamic,
    JumpDynamicConditional,
    Call,
    CallDynamic,
    Return,
    Syscall,
    Sysret,
    Bug,
    Nop,
    Stac,
    Clac,
    Std,
    Cld,
    Trap,
    Endbr,
    LeaRip,
}

// The 17 registers tracked by x86 objtool's CFI state.  ReturnAddress is a
// logical CFI slot, not a hardware register.
enum X86Register {
    Ax,
    Cx,
    Dx,
    Bx,
    Sp,
    Bp,
    Si,
    Di,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    ReturnAddress,
}

// These fixed-mode enums encode the invariants which are implicit in
// objtool's op_{src,dest}.  There is no meaningless register field for a
// push/pop, and only address-bearing variants carry an offset.
enum StackDestination {
    Register { register: X86Register },
    RegisterIndirect { register: X86Register, offset: i32 },
    Memory,
    Push,
    PushFlags,
}

enum StackSource {
    Register { register: X86Register },
    RegisterIndirect { register: X86Register, offset: i32 },
    Constant { value: i32 },
    Pop,
    PopFlags,
    Add { register: X86Register, value: i32 },
    And { register: X86Register, value: i32 },
}

// CFG edge kinds deliberately describe why an edge exists.  That keeps
// alternatives and exception fixups distinct when the validator chooses
// which joins need identical stack state.
enum CfgEdgeKind {
    Fallthrough,
    DirectJump,
    IndirectJump,
    Call,
    Alternative,
    JumpTable,
    ExceptionFixup,
}

// cfi_reg::base is either a real register or one of four sentinel values.
// An enum prevents the negative sentinel values from being confused with a
// register number.
enum CfiBase {
    Undefined,
    Cfa,
    StackPointerIndirect,
    FramePointerIndirect,
    Register { register: X86Register },
}

struct CfiRule {
    base: CfiBase,
    offset: i32,
}

enum OptionalRegister {
    None,
    Some { register: X86Register },
}

// Numeric values are intentionally not treated as an ABI.  The eventual ORC
// writer must encode these variants explicitly into Linux's three-bit field.
enum UnwindType {
    Undefined,
    EndOfStack,
    Call,
    Registers,
    RegistersPartial,
}

struct InstructionFlags {
    dead_end: bool,
    ignore_alternatives: bool,
    hint: bool,
    save: bool,
    restore: bool,
    retpoline_safe: bool,
    no_endbr: bool,
    unret: bool,
    no_relocation: bool,
    hole: bool,
    fake: bool,
    trace: bool,
    visited: u8,
}

// Cross-pool links below are four-byte, pool-relative offsets.  The names of
// their target pools are resolved module-wide, so the mutually linked record
// types can remain direct and allocation-free.
struct Instruction {
    section_index: u32,
    offset: u64,
    immediate: u64,
    length: u8,
    previous_length: u8,
    immediate_length: u8,
    kind: InstructionKind,
    hint_instruction: i8,
    flags: InstructionFlags,
    first_edge: CfgEdge&<u32 in cfg_edge_pool>?,
    last_edge: CfgEdge&<u32 in cfg_edge_pool>?,
    first_stack_op: StackOperation&<u32 in stack_op_pool>?,
    last_stack_op: StackOperation&<u32 in stack_op_pool>?,
    analysis_state: AnalysisState&<u32 in analysis_state_pool>?,
}

struct CfgEdge {
    source: Instruction&<u32 in instruction_pool>,
    // Null represents a decoded but as-yet unresolved indirect/external edge.
    target: Instruction&<u32 in instruction_pool>?,
    next_from_source: CfgEdge&<u32 in cfg_edge_pool>?,
    kind: CfgEdgeKind,
}

struct StackOperation {
    owner: Instruction&<u32 in instruction_pool>,
    next: StackOperation&<u32 in stack_op_pool>?,
    destination: StackDestination,
    source: StackSource,
}

// This mirrors the information in Linux's cfi_state plus insn_state.  Fixed
// arrays make each state indexable and independently copyable; they also keep
// the state pool fixed-stride.
struct AnalysisState {
    registers: CfiRule[17],
    values: CfiRule[17],
    cfa: CfiRule,
    stack_size: i32,
    drap_register: OptionalRegister,
    drap_offset: i32,
    unwind_type: UnwindType,
    bp_scratch: bool,
    drap: bool,
    signal: bool,
    end: bool,
    force_undefined: bool,
    uaccess_stack: u32,
    uaccess: bool,
    direction_flag: bool,
    noinstr: bool,
    hint_instruction: i8,
}

// One process analyzes one object.  Typed IDs and relative references pin
// these pools against shrinking, which is exactly the desired lifetime.
var instruction_pool: Instruction[>..] = [];
var cfg_edge_pool: CfgEdge[>..] = [];
var stack_op_pool: StackOperation[>..] = [];
var analysis_state_pool: AnalysisState[>..] = [];

type InstructionId = u32 in instruction_pool;
type CfgEdgeId = u32 in cfg_edge_pool;
type StackOperationId = u32 in stack_op_pool;
type AnalysisStateId = u32 in analysis_state_pool;

fn empty_instruction_flags() -> InstructionFlags {
    InstructionFlags {
        dead_end: false,
        ignore_alternatives: false,
        hint: false,
        save: false,
        restore: false,
        retpoline_safe: false,
        no_endbr: false,
        unret: false,
        no_relocation: false,
        hole: false,
        fake: false,
        trace: false,
        visited: 0,
    }
}

fn new_instruction(section_index: u32, offset: u64, length: u8,
                   kind: InstructionKind) -> Instruction {
    Instruction {
        section_index: section_index,
        offset: offset,
        immediate: 0,
        length: length,
        previous_length: 0,
        immediate_length: 0,
        kind: kind,
        hint_instruction: 0,
        flags: empty_instruction_flags(),
        first_edge: null,
        last_edge: null,
        first_stack_op: null,
        last_stack_op: null,
        analysis_state: null,
    }
}

fn add_instruction(section_index: u32, offset: u64, length: u8,
                   kind: InstructionKind) -> InstructionId {
    let index = instruction_pool.len;
    instruction_pool.push(new_instruction(section_index, offset, length, kind));
    return index as InstructionId;
}

fn append_cfg_edge(source: InstructionId,
                   target: Instruction&<u32 in instruction_pool>?,
                   kind: CfgEdgeKind) -> CfgEdgeId {
    let index = cfg_edge_pool.len;
    let edge .= cfg_edge_pool.push(CfgEdge {
        source: instruction_pool[source],
        target: target,
        next_from_source: null,
        kind: kind,
    });
    let instruction .= instruction_pool[source];
    let tail = instruction.last_edge;
    if tail { tail.next_from_source .= edge; }
    else { instruction.first_edge .= edge; }
    instruction.last_edge .= edge;
    return index as CfgEdgeId;
}

fn add_cfg_edge(source: InstructionId, target: InstructionId,
                kind: CfgEdgeKind) -> CfgEdgeId {
    append_cfg_edge(source, instruction_pool[target], kind)
}

fn add_unresolved_cfg_edge(source: InstructionId,
                           kind: CfgEdgeKind) -> CfgEdgeId {
    append_cfg_edge(source, null, kind)
}

fn add_stack_operation(owner: InstructionId, destination: StackDestination,
                       source: StackSource) -> StackOperationId {
    let index = stack_op_pool.len;
    let operation .= stack_op_pool.push(StackOperation {
        owner: instruction_pool[owner],
        next: null,
        destination: destination,
        source: source,
    });
    let instruction .= instruction_pool[owner];
    let tail = instruction.last_stack_op;
    if tail { tail.next .= operation; }
    else { instruction.first_stack_op .= operation; }
    instruction.last_stack_op .= operation;
    return index as StackOperationId;
}

fn register_index(register: X86Register) -> i64 {
    match register {
        Ax => 0,
        Cx => 1,
        Dx => 2,
        Bx => 3,
        Sp => 4,
        Bp => 5,
        Si => 6,
        Di => 7,
        R8 => 8,
        R9 => 9,
        R10 => 10,
        R11 => 11,
        R12 => 12,
        R13 => 13,
        R14 => 14,
        R15 => 15,
        ReturnAddress => 16,
    }
}

fn undefined_cfi_rule() -> CfiRule {
    CfiRule { base: CfiBase.Undefined, offset: 0 }
}

fn empty_analysis_state() -> AnalysisState {
    let undefined = undefined_cfi_rule();
    AnalysisState {
        registers: [undefined; 17],
        values: [undefined; 17],
        cfa: undefined,
        stack_size: 0,
        drap_register: OptionalRegister.None,
        drap_offset: 0,
        unwind_type: UnwindType.Undefined,
        bp_scratch: false,
        drap: false,
        signal: false,
        end: false,
        force_undefined: false,
        uaccess_stack: 0,
        uaccess: false,
        direction_flag: false,
        noinstr: false,
        hint_instruction: 0,
    }
}

// Initial state for an ordinary callable x86-64 function:
// CFA = rsp + 8, return address = CFA - 8, logical stack size = 8.
fn initial_function_state() -> AnalysisState {
    var state = empty_analysis_state();
    state.cfa = CfiRule {
        base: CfiBase.Register { register: X86Register.Sp },
        offset: 8,
    };
    state.registers[register_index(X86Register.ReturnAddress)] = CfiRule {
        base: CfiBase.Cfa,
        offset: -8,
    };
    state.stack_size = 8;
    state.unwind_type = UnwindType.Call;
    return state;
}

fn add_analysis_state(state: AnalysisState) -> AnalysisStateId {
    let index = analysis_state_pool.len;
    analysis_state_pool.push(state);
    return index as AnalysisStateId;
}

fn set_analysis_state(instruction: InstructionId, state: AnalysisStateId) {
    instruction_pool[instruction].analysis_state .= analysis_state_pool[state];
}
