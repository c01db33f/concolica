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

import logging

from termcolor import colored

import reil


# TODO: this code doesn't belong here, but it doesn't belong in emulator.py either.
# put it somewhere sensible as and when something else starts using this code.

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

   # for r in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15']:
   #     if r in s.registers:
   #         if s.registers[r].symbolic:
   #             output += '{0}: symbolic\n'.format(r)
   #         else:
   #             output += '{0}: {1}\n'.format(r, s.registers[r])

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


VULNERABILITY = 41
OUTPUT = 28
SYSCALL = 27
FUNCTION_CALL = 26
FORKING = 25
NATIVE_INSTRUCTION = 24
NATIVE_REGISTERS = 23
REIL_INSTRUCTION = 22
REIL_REGISTERS = 21


class Formatter(logging.Formatter):

    color_map = {
        VULNERABILITY:['white', 'on_red'],
        OUTPUT:['white'],
        SYSCALL:['blue'],
        FUNCTION_CALL:['blue'],
        NATIVE_INSTRUCTION:['yellow'],
        REIL_INSTRUCTION:['magenta']
    }

    def __init__(self, fmt, datefmt=None):
        logging.Formatter.__init__(self, fmt, datefmt)

    def format(self, record):
        message = logging.Formatter.format(self, record)

        if record.levelno in self.color_map:
            return colored(message, *self.color_map[record.levelno])
        else:
            return message


class StateLogger(logging.LoggerAdapter):

    def __init__(self, state):
        logging.LoggerAdapter.__init__(self, logging.getLogger('concolica'), {'state': state.id})
        self.state = state

    def vulnerability(self, v):
        self.log(VULNERABILITY,
                 '{:5} {}'.format(self.state.id, v))

    def output(self, msg):
        self.log(OUTPUT, msg)

    def syscall(self, f, msg, *args):
        self.log(SYSCALL,
                 '{:5} {} {}'.format(self.state.id, f.return_address(), msg.format(*args)))

    def function_call(self, f, msg, *args):
        if f is not None:
            self.log(FUNCTION_CALL,
                     '{:5} {} {}'.format(self.state.id, f.return_address(), msg.format(*args)))
        else:
            self.log(FUNCTION_CALL,
                     '{:5} {}'.format(self.state.id, msg.format(*args)))

    def native_instruction(self, hc, i, x86_64):
        self.log(NATIVE_REGISTERS,
                 register_dump(self.state, x86_64))

        self.log(NATIVE_INSTRUCTION,
                 '{:5} {:6} {}'.format(self.state.id, hc, i))

    def reil_instruction(self, i):
        self.log(REIL_REGISTERS,
                 reil_register_dump(self.state, i))

        self.log(REIL_INSTRUCTION,
                 '{:5} {:4} {}'.format(self.state.id, self.state.il_index-1, i))

    def fork(self, id):
        self.log(FORKING, '{:5} forking {}'.format(self.state.id, id))