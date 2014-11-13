# -*- coding: utf-8 -*-

#    Copyright 2014 Mark Brand - c01db33f (at) gmail.com
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.


import reil
import reil.x86.translator as x86

from concolica.utils import *
from concolica.vulnerabilities import *

from smt import bitvector as bv


def operand_value(s, o):
    output = o
    if isinstance(o, reil.ImmediateOperand):
        output = bv.Constant(o.size, o.value)
    elif isinstance(o, reil.RegisterOperand):
        output = s.registers[o.name]
        if output.size > o.size:
            output = output.extract(o.size)
        elif output.size < o.size:
            output = output.zero_extend_to(o.size)
    return output


def op_add(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a + b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_and(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a & b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_bisz(i, s):
    a = operand_value(s, i.input0)
    dst = i.output

    result = bv.if_then_else(
        a == bv.Constant(a.size, 0),
        bv.Constant(dst.size, 1),
        bv.Constant(dst.size, 0))

    s.registers[dst.name] = result
    return [s]


def op_bsh(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    # TODO: support symbolic shifts

    if b.value >= 0:
        result = a << b
    else:
        result = a >> bv.Constant(b.size, abs(b.value))
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_div(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a // b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_jcc(i, s):
    ss = []
    a = operand_value(s, i.input0)
    dst = operand_value(s, i.output)

    branch = a.can_be_nonzero()
    dont_branch = a.can_be_zero()

    if s.solver.check(branch):
        if s.solver.check(dont_branch):
            # we take both options, current state doesn't branch
            # and new state takes the branch
            a = s.fork()
            a.solver.add(branch)
            ss += a.branch(dst)

            b = s.fork()
            b.solver.add(dont_branch)
            ss.append(b)
        else:
            # we branch only, no need to add the constraint
            ss = s.branch(dst)
    else:
        # we don't branch and no need to add the constraint
        ss = [s]

    return ss


def op_ldm(i, s):
    src = operand_value(s, i.input0)
    dst = i.output

    s.registers[dst.name] = s.read(src, dst.size)
    if s.registers[dst.name] is None:
        import pdb
        pdb.set_trace()
    return [s]


def op_mod(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a % b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_mul(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a * b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_nop(i, s):
    return [s]


def op_or(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a | b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_stm(i, s):
    val = operand_value(s, i.input0)
    dst = operand_value(s, i.output)

    s.write(dst, val)
    return [s]


def op_str(i, s):
    src = operand_value(s, i.input0)
    dst = i.output

    src = src.resize(dst.size)

    s.registers[dst.name] = src
    return [s]


def op_sub(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a - b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_undef(i, s):
    reg = i.input0
    if reg.name in s.registers:
        s.registers[reg.name] = None
    return [s]


def op_unkn(i, s):
    raise NotImplementedError()


def op_xor(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a ^ b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


# XREIL extensions

def op_bisnz(i, s):
    a = operand_value(s, i.input0)
    dst = i.output

    result = bv.if_then_else(
        a != bv.Constant(a.size, 0),
        bv.Constant(dst.size, 1),
        bv.Constant(dst.size, 0))

    s.registers[dst.name] = result
    return [s]


def op_equ(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    result = bv.if_then_else(
        a == b,
        bv.Constant(dst.size, 1),
        bv.Constant(dst.size, 0))

    s.registers[dst.name] = result
    return [s]


def op_lshl(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a << b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_lshr(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a.logical_shift_right(b)
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_ashr(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a >> b
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_sdiv(i, s):
    a = operand_value(s, i.input0)
    b = operand_value(s, i.input1)
    dst = i.output

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = bv.BinaryOperation(a, bv.BinaryOperator.SignedDivide, b)
    result = result.resize(dst.size)

    s.registers[dst.name] = result
    return [s]


def op_sex(i, s):
    a = operand_value(s, i.input0)
    dst = i.output

    value = a.sign_extend_to(dst.size)

    s.registers[dst.name] = value
    return [s]


def op_sys(i, s):
    return s.kernel.dispatch(s, i)

opcode_map = {
    reil.ADD:   op_add,
    reil.AND:   op_and,
    reil.BISZ:  op_bisz,
    reil.BSH:   op_bsh,
    reil.DIV:   op_div,
    reil.JCC:   op_jcc,
    reil.LDM:   op_ldm,
    reil.MOD:   op_mod,
    reil.MUL:   op_mul,
    reil.NOP:   op_nop,
    reil.OR:    op_or,
    reil.STM:   op_stm,
    reil.STR:   op_str,
    reil.SUB:   op_sub,
    reil.UNDEF: op_undef,
    reil.UNKN:  op_unkn,
    reil.XOR:   op_xor,

    reil.BISNZ: op_bisnz,
    reil.EQU:   op_equ,
    reil.LSHL:  op_lshl,
    reil.LSHR:  op_lshr,
    reil.ASHR:  op_ashr,
    reil.SDIV:  op_sdiv,
    reil.SEX:   op_sex,
    reil.SYS:   op_sys,
}


def reil_single_step(ri, s):
    return opcode_map[ri.opcode](ri, s)


_translation_cache = dict()
_hit_count = dict()


def fetch_instruction(s, x86_64=False):
    ip = s.ip
    s.trace.append(ip)

    if ip not in _translation_cache:
        bs = []

        for i in range(0, 128):
            try:
                bs.append(s.memory.read_byte(s, ip + i))
            except IndexError():
                break

        bs = ''.join(map(lambda x: chr(x.value), bs))
        for i in x86.translate(bs, ip, x86_64):
            _translation_cache[i.address] = i

    if ip not in _translation_cache:
        raise InvalidExecution(s, ip)

    i = _translation_cache[ip]
    s.ip += i.size

    if x86_64:
        s.registers['rip'] = bv.Constant(64, s.ip)

    return i


def single_step(s, x86_64=False):
    i = fetch_instruction(s, x86_64)
    if i is None:
        return []

    #if i.address == 0x400a78:
    #    raise InvalidWrite(s, 0xc01db33f, 0xc01db33f)

    # yes, this is not thread-safe. it should only be used for something like
    # selecting best path though, so it doesn't really matter/is fuzzy anyway.
    if i.address in _hit_count:
        hc = _hit_count[i.address] = _hit_count[i.address] + 1
    else:
        hc = _hit_count[i.address] = 1

    if i.address in s.symbols:
        symbol = s.symbols[i.address]
        if s.symbols[i.address] in s.function_hooks:
            ss = s.function_hooks[symbol](s)
            for s in ss:

                # any state needing more than 60 seconds in it's last solver
                # invocation needs to be concretised.
                if s.solver.solve_time() > 30:
                    s.log.warning('concretising (last solve took: {}s)', s.solver.solve_time)
                    s.solver.concretise()

                # remove temporary registers
                s.clear_il_state()

            return ss
        else:
            s.log.function_call(None, symbol)

    s.log.native_instruction(hc, i, x86_64)

    max_il_index = len(i.il_instructions)

    states = [s]
    exit_states = []

    while len(states) > 0:
        s = states.pop()

        if s.il_index >= max_il_index:

            # any state needing more than 60 seconds in it's last solver
            # invocation needs to be concretised.
            if s.solver.solve_time() > 30:
                s.log.warning('concretising (last solve took: {}s)'.format(s.solver.solve_time()))
                s.solver.concretise()

            # remove temporary registers
            s.clear_il_state()

            exit_states.append(s)
            continue

        ri = i.il_instructions[s.il_index]
        s.il_index += 1

        s.log.reil_instruction(ri)

        states += reil_single_step(ri, s)

    return exit_states