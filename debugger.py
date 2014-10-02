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


import struct
import sys

import vtrace
import vdb
from envi.archs.i386 import *
from envi.archs.amd64 import *

import argparse
import functools
import os
import shlex
import struct
import subprocess

from termcolor import colored

from concolica import memory
from concolica import state

from smt import bitvector as bv


class VdbProcess(object):

    def __init__(self, trace):
        self._t = trace


    def _load_memory(self):
        global_memory = memory.StaticMemory()

        maps = self._t.getMemoryMaps()

        for base, size, perm, name in maps:
            try:
                bytes = self._t.readMemory(base, size)
                global_memory.add_mapping(base, bytes)
            except:
                pass

        return memory.DynamicMemory(global_memory)


    def _load_symbols(self):
        symbols = dict()

        self._t._findLibraryMaps('\x7fELF')

        for lib_name in self._t.getNormalizedLibNames():
            if lib_name == '[vdso]':
                continue
            for sym in self._t.getSymsForFile(lib_name):
                if len(sym.name) == 0:
                    continue
                if sym.value not in symbols or len(sym.name) < len(symbols[sym.value]):
                    symbols[sym.value] = sym.name

        return symbols

    def _load_registers(self, state):
        raise NotImplementedError()

    def state(self):
        s = state.State()
        s.memory = self._load_memory()
        s.symbols = self._load_symbols()
        self._load_registers(s)
        return s


class VdbX86Process(VdbProcess):

    def __init__(self, trace):
        VdbProcess.__init__(self, trace)


    def _get_gsbase(self):
        sp = self._t.getStackCounter()
        pc = self._t.getProgramCounter()

        regsave = self._t.getRegisters()
        spsave = self._t.readMemory(sp, 16)
        pcsave = self._t.readMemory(pc, 16)

        self._t.writeMemory(pc, '\x65\xa1\x00\x00\x00\x00')
        self._t._syncRegs()

        try:
            tid = self._t.getMeta('ThreadId', 0)
            self._t.platformStepi()
            os.waitpid(tid, 0)
            eax = self._t.getRegisterByName('eax')

            return eax
        finally:
            self._t.writeMemory(sp, spsave)
            self._t.writeMemory(pc, pcsave)
            self._t.setRegisters(regsave)


    def _load_registers(self, state):
        context = self._t.getRegisterContext(self._t.getCurrentThread())

        state.ip = context.getProgramCounter()

        for reg in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']:
            state.registers[reg] = bv.Constant(32, context.getRegisterByName(reg))

        for reg in ['cf', 'pf', 'af', 'zf', 'sf', 'df', 'of']:
            state.registers[reg] = bv.Constant(8, context.getRegisterByName(reg.upper()))

        # vdb doesn't appear to read xmm registers...

        for reg in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']:
            state.registers[reg] = bv.Constant(128, context.getRegisterByName(reg))

        state.registers['gsbase'] = bv.Constant(32, self._get_gsbase())


class VdbX86_64Process(VdbProcess):

    def __init__(self, trace):
        VdbProcess.__init__(self, trace)


    def _get_fsbase(self):
        sp = self._t.getStackCounter()
        pc = self._t.getProgramCounter()

        regsave = self._t.getRegisters()
        spsave = self._t.readMemory(sp, 8)
        pcsave = self._t.readMemory(pc, 2)

        __arch_prctl = 0x9e

        self._t.writeMemory(pc, '\x0f\x05')
        self._t.setRegisterByName('rax', __arch_prctl)
        self._t.setRegisterByName('rdi', 0x1003)
        self._t.setRegisterByName('rsi', sp)
        self._t._syncRegs()

        try:
            tid = self._t.getMeta('ThreadId', 0)
            self._t.platformStepi()
            os.waitpid(tid, 0)
            rax = self._t.getRegisterByName('rax')
            if rax & 0x8000000000000000:
                print 'arch_prctl failed! {:x}'.format(rax)
            else:
                return struct.unpack('<Q', self._t.readMemory(sp, 8))[0]
        finally:
            self._t.writeMemory(sp, spsave)
            self._t.writeMemory(pc, pcsave)
            self._t.setRegisters(regsave)


    def _get_gsbase(self):
        sp = self._t.getStackCounter()
        pc = self._t.getProgramCounter()

        regsave = self._t.getRegisters()
        spsave = self._t.readMemory(sp, 8)
        pcsave = self._t.readMemory(pc, 2)

        __arch_prctl = 0x9e

        self._t.writeMemory(pc, '\x0f\x05')
        self._t.setRegisterByName('rax', __arch_prctl)
        self._t.setRegisterByName('rdi', 0x1004)
        self._t.setRegisterByName('rsi', sp)
        self._t._syncRegs()

        try:
            tid = self._t.getMeta('ThreadId', 0)
            self._t.platformStepi()
            os.waitpid(tid, 0)
            rax = self._t.getRegisterByName('rax')
            if rax & 0x8000000000000000:
                print 'arch_prctl failed! {:x}'.format(rax)
            else:
                return struct.unpack('<Q', self._t.readMemory(sp, 8))[0]
        finally:
            self._t.writeMemory(sp, spsave)
            self._t.writeMemory(pc, pcsave)
            self._t.setRegisters(regsave)


    def _load_registers(self, state):
        context = self._t.getRegisterContext(self._t.getCurrentThread())

        state.ip = context.getProgramCounter()

        for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            state.registers[reg] = bv.Constant(64, context.getRegisterByName(reg))

        for reg in ['cf', 'pf', 'af', 'zf', 'sf', 'df', 'of']:
            state.registers[reg] = bv.Constant(8, context.getRegisterByName(reg.upper()))

        # vdb doesn't appear to read xmm registers

        for reg in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15']:
            state.registers[reg] = bv.Constant(128, context.getRegisterByName('x' + reg[1:]) & 0xffffffffffffffffffffffffffffffff)

        state.registers['fsbase'] = bv.Constant(64, self._get_fsbase())
        state.registers['gsbase'] = bv.Constant(64, self._get_gsbase())


def get_state(program, breakpoint, x86_64=False):

    state = None
    trace = vtrace.getTrace()

    print '[*] starting process'

    trace.execute(program)

    class Tracepoint(vtrace.Breakpoint):

        def __init__(self):
            vtrace.Breakpoint.__init__(self, breakpoint)

        def notify(self, event, trace):
            print '[*] asdf'
            if x86_64:
                p = VdbX86_64Process(trace)
            else:
                p = VdbX86Process(trace)

            print '[*] reached breakpoint, dumping state'
            state = p.state()

            while True:
                pass

            raise ValueError()

    trace.addBreakpoint(Tracepoint())

    print '[*] debugger attached'

    try:
        trace.run()
    except ValueError:
        trace.kill()

    return state

