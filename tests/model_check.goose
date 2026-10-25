// SPDX-License-Identifier: GPL-2.0-or-later
// Focused compile/run proof for the fixed-size objtool model and its pools.
import std;
import model from "../src";

fn main() {
    let entry = model::add_instruction(
        1, 0, 1, model::InstructionKind.Nop);
    let body = model::add_instruction(
        1, 1, 5, model::InstructionKind.Call);
    let exit = model::add_instruction(
        1, 6, 1, model::InstructionKind.Return);

    let fallthrough = model::add_cfg_edge(
        entry, body, model::CfgEdgeKind.Fallthrough);
    let call = model::add_unresolved_cfg_edge(
        body, model::CfgEdgeKind.Call);
    let continuation = model::add_cfg_edge(
        body, exit, model::CfgEdgeKind.Fallthrough);

    let push = model::add_stack_operation(
        body,
        model::StackDestination.Push,
        model::StackSource.Constant { value: 0 });
    let adjust = model::add_stack_operation(
        body,
        model::StackDestination.Register {
            register: model::X86Register.Sp,
        },
        model::StackSource.Add {
            register: model::X86Register.Sp,
            value: -8,
        });

    let state = model::add_analysis_state(model::initial_function_state());
    model::set_analysis_state(entry, state);

    // A validator worklist carries branded IDs, not ordinary references.
    // The brand survives a grow-shrink pop and remains a checked-free index
    // into the grow-only instruction pool.
    var worklist: model::InstructionId[>..<] = [];
    worklist.push(entry);
    worklist.push(body);
    let current = worklist.pop();

    assert(model::instruction_pool.len == 3);
    assert(model::cfg_edge_pool.len == 3);
    assert(model::stack_op_pool.len == 2);
    assert(model::analysis_state_pool.len == 1);
    assert(model::cfg_edge_pool[fallthrough].target .==
           model::instruction_pool[body]);
    assert(!model::cfg_edge_pool[call].target);
    assert(model::cfg_edge_pool[continuation].target .==
           model::instruction_pool[exit]);
    assert(model::instruction_pool[entry].analysis_state .==
           model::analysis_state_pool[state]);
    assert(model::instruction_pool[body].first_stack_op .==
           model::stack_op_pool[push]);
    assert(model::stack_op_pool[push].next .==
           model::stack_op_pool[adjust]);
    assert(model::analysis_state_pool[state].stack_size == 8);
    assert(model::analysis_state_pool[state].cfa.offset == 8);
    assert(model::register_index(model::X86Register.ReturnAddress) == 16);
    assert(model::instruction_pool[current].offset == 1);

    print("model pools ok");
}
