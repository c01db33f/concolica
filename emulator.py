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


from termcolor import colored

import reil
import reil.x86.translator as x86

import smt.bitvector as bv

from concolica import global_state
from concolica.utils import *


def operand_value(s, o):
    output = o
    if isinstance(o, pyreil.ImmediateOperand):
        output = bv.Constant(o.size, o.value)
    elif isinstance(o, pyreil.RegisterOperand):
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

    value = None

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

    value = None

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

    value = None

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

    value = None

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

    new = None
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

    value = None

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

    value = None

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

    value = None

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

    value = None

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

    value = None

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

    value = None

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

    value = None

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

    value = None

    operation_size = max(a.size, b.size, dst.size)

    a = a.resize(operation_size)
    b = b.resize(operation_size)

    result = a >> b
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
    reil.ADD:  op_add,
    reil.AND:  op_and,
    reil.BISZ: op_bisz,
    reil.BSH:  op_bsh,
    reil.DIV:  op_div,
    reil.JCC:  op_jcc,
    reil.LDM:  op_ldm,
    reil.MOD:  op_mod,
    reil.MUL:  op_mul,
    reil.NOP:  op_nop,
    reil.OR:   op_or,
    reil.STM:  op_stm,
    reil.STR:  op_str,
    reil.SUB:  op_sub,
    reil.UNDEF:op_undef,
    reil.UNKN: op_unkn,
    reil.XOR:  op_xor,

    reil.BISNZ:op_bisnz,
    reil.EQU:  op_equ,
    reil.LSHL: op_lshl,
    reil.LSHR: op_lshr,
    reil.ASHR: op_ashr,
    reil.SEX:  op_sex,
    reil.SYS:  op_sys,
}


def reil_single_step(ri, s):
    return opcode_map[ri.opcode](ri, s)


def reil_register_dump(s, ri):
    output = ''

    interesting = []

    if isinstance(ri.input0, reil.TemporaryOperand):
        interesting.append(ri.input0.name)

    if isinstance(ri.input1, reil.TemporaryOperand):
        interesting.append(ri.input1.name)

    for r in interesting:
        if s.registers[r].symbolic:
            output += '{0:2}: symbolic\n'.format(r)
        else:
            output += '{0:2}: {1}\n'.format(r, s.registers[r])

    if len(output) > 0:
        output = output[:-1]

    return output


def x86_register_dump(s):
    output = ''
    for r in ['eax', 'ebx', 'ecx', 'edx']:
        if r in s.registers and s.registers[r] is not None:
            if s.registers[r].symbolic:
                output += '{0}: symbolic   '.format(r)
            else:
                output += '{0}: {1}   '.format(r, s.registers[r])
        else:
            output += '{0}:            '.format(r)
    output += '\n'

    for r in ['esi', 'edi', 'ebp', 'esp']:
        if r in s.registers and s.registers[r] is not None:
            if s.registers[r].symbolic:
                output += '{0}: symbolic   '.format(r)
            else:
                output += '{0}: {1}   '.format(r, s.registers[r])
        else:
            output += '{0}:            '.format(r)
    output += '\n'

    for r in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']:
        if r in s.registers and s.registers[r] is not None:
            if s.registers[r].symbolic:
                output += '{0}: symbolic\n'.format(r)
            elif s.registers[r].value != 0:
                output += '{0}: {1}\n'.format(r, s.registers[r])

    for r in ['cf', 'pf', 'af', 'zf', 'sf', 'df', 'of']:
        if r in s.registers and s.registers[r] is not None:
            if s.registers[r].symbolic:
                output += ' {0}: s  '.format(r)
            elif s.registers[r].value != 0:
                output += ' {0}: 1  '.format(r)
            else:
                output += ' {0}: 0  '.format(r)
        else:
            output += ' ' + r + ':    '
    return output


def x86_64_register_dump(s):
    output = ''
    for r in ['rax', 'rbx', 'rcx', 'rdx']:
        if r in s.registers and s.registers[r] is not None:
            if s.registers[r].symbolic:
                output += '{0}: symbolic           '.format(r)
            else:
                output += '{0}: {1}   '.format(r, s.registers[r])
        else:
            output += '{0}:                    '.format(r)
    output += '\n'

    for r in ['rsi', 'rdi', 'rbp', 'rsp']:
        if r in s.registers and s.registers[r] is not None:
            if s.registers[r].symbolic:
                output += '{0}: symbolic           '.format(r)
            else:
                output += '{0}: {1}   '.format(r, s.registers[r])
        else:
            output += '{0}:                    '.format(r)
    output += '\n'

    for r in ['r8', 'r9', 'r10', 'r11']:
        if r in s.registers and s.registers[r] is not None:
            if s.registers[r].symbolic:
                output += '{0:3}: symbolic           '.format(r)
            else:
                output += '{0:3}: {1}   '.format(r, s.registers[r])
        else:
            output += '{0:3}:                    '.format(r)
    output += '\n'

    for r in ['r12', 'r13', 'r14', 'r15']:
        if r in s.registers and s.registers[r] is not None:
            if s.registers[r].symbolic:
                output += '{0}: symbolic           '.format(r)
            else:
                output += '{0}: {1}   '.format(r, s.registers[r])
        else:
            output += '{0}:                    '.format(r)
    output += '\n'

    #for r in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15']:
    #    if r in s.registers:
    #        if s.registers[r].symbolic:
    #            output += '{0}: symbolic\n'.format(r)
    #        else:
    #            output += '{0}: {1}\n'.format(r, s.registers[r])

    for r in ['cf', 'pf', 'af', 'zf', 'sf', 'df', 'of']:
        if r in s.registers and s.registers[r] is not None:
            if s.registers[r].symbolic:
                output += ' {0}: s  '.format(r)
            elif s.registers[r].value != 0:
                output += ' {0}: 1  '.format(r)
            else:
                output += ' {0}: 0  '.format(r)
        else:
            output += ' ' + r + ':    '
    return output


def register_dump(s, x86_64=False):
    if x86_64:
        return x86_64_register_dump(s)
    else:
        return x86_register_dump(s)


_translation_cache = dict()
def fetch_instruction(s, x86_64=False):
    ip = s.ip

    if ip not in _translation_cache:
        bytes = []

        for i in range(0, 128):
            try:
                bytes.append(s.memory[ip + i])
            except:
                break

        bytes = ''.join(map(lambda x:chr(x.value), bytes))
        for i in x86.translate(bytes, ip, x86_64):
            _translation_cache[i.address] = i

    if ip not in _translation_cache:
        #sp = s.registers['esp']
        #print s.memory.dump(range(sp.value, sp.value + 128))
        print '{} invalid ip {:08x}'.format(s.id, ip)
        return None

    i = _translation_cache[ip]
    s.ip += i.size

    if x86_64:
        s.registers['rip'] = bv.Constant(64, s.ip)

    return i


hit_count = dict()
def single_step(s, x86_64=False):
    i = fetch_instruction(s, x86_64)
    if i is None:
        return []

    if i.address in hit_count:
        hc = hit_count[i.address] = hit_count[i.address] + 1
    else:
        hc = hit_count[i.address] = 1

    #print ''
    if i.address in global_state.symbols:
        symbol = global_state.symbols[i.address]
        if global_state.symbols[i.address] in global_state.function_hooks:
            ss = global_state.function_hooks[symbol](s)
            for s in ss:
                #s.solver.check()
                s.clear_il_state()
            return ss
        else:
            print colored('{} calling {}'.format(s.id, symbol), 'green')

    print colored(register_dump(s, x86_64), 'blue')
    print colored('{} {:4} {}'.format(s.id, hc, i), 'yellow')

    max_il_index = len(i.il_instructions)

    states = [s]
    exit_states = []

    while len(states) > 0:
        s = states.pop()

        if s.il_index >= max_il_index:
            #s.solver.check()
            s.clear_il_state()
            exit_states.append(s)
            continue

        ri = i.il_instructions[s.il_index]
        s.il_index += 1

        print ''
        print colored(reil_register_dump(s, ri), 'magenta')
        print colored('{:2} {}'.format(s.il_index-1, ri), 'magenta')

        states += reil_single_step(ri, s)

    return exit_states