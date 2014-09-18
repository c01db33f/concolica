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

from smt import boolean as bl
from smt import bitvector as bv

from concolica.utils import *

class Cdecl(object):

    class Parameters(object):

        def __init__(self, state):
            self.state = state

        def __getitem__(self, index):
            esp = self.state.registers['esp']
            param_address = esp + bv.Constant(32, 4 + (4 * index))
            return self.state.read(param_address, 32)


    class VaArgs(object):

        def __init__(self, state, address):
            self.state = state
            self.address = address

        def copy(self, new_state):
            new = Cdecl.VaArgs(new_state, self.address)
            return new

        def __getitem__(self, index):
            return self.state.read(self.address + bv.Constant(32, (4 * index)), 32)


    def __init__(self, state):
        self.state = state
        self.params = self.Parameters(state)


    def return_address(self):
        esp = self.state.registers['esp']
        return self.state.read(esp, 32)


    def ret(self, value=None):
        # load return address, adjust stack pointer
        esp = self.state.registers['esp']
        self.state.registers['esp'] = esp + bv.Constant(32, 4)
        return_address = self.state.read(esp, 32)

        # set return value (if set)
        if value is not None:
            if isinstance(value, int):
                self.state.registers['eax'] = bv.Constant(32, value)
            elif isinstance(value, str):
                self.state.registers['eax'] = bv.Symbol(32, unique_name(value))
            else:
                self.state.registers['eax'] = value

        return self.state.branch(return_address)


    def va_args(self, index):
        esp = self.state.registers['esp']
        address = esp + bv.Constant(32, 4 + (4 * index))
        return self.VaArgs(self.state, address)



class Amd64SysV(object):

    class Parameters(object):

        def __init__(self, state):
            self.state = state

        def __getitem__(self, index):
            if index == 0:
                return self.state.registers['rdi']
            elif index == 1:
                return self.state.registers['rsi']
            elif index == 2:
                return self.state.registers['rdx']
            elif index == 3:
                return self.state.registers['rcx']
            elif index == 4:
                return self.state.registers['r8']
            elif index == 5:
                return self.state.registers['r9']
            else:
                raise 'crap...'

    class VaArgs(object):

        def __init__(self, params, index):
            self.params = params
            self.index = index

        def __getitem__(self, index):
            return self.params[self.index + index]

    def __init__(self, state):
        self.state = state
        self.params = self.Parameters(state)

    def return_address(self):
        rsp = self.state.registers['rsp']
        return self.state.read(rsp, 64)

    def ret(self, value=None):
        # load return address, adjust stack pointer
        rsp = self.state.registers['rsp']
        self.state.registers['rsp'] = rsp + bv.Constant(64, 8)
        return_address = self.state.read(rsp, 64)

        # set return value (if set)
        if value is not None:
            if isinstance(value, int) or isinstance(value, long):
                self.state.registers['rax'] = bv.Constant(64, value)
            elif isinstance(value, str):
                self.state.registers['rax'] = bv.Symbol(64, unique_name(value))
            else:
                self.state.registers['rax'] = value

        return self.state.branch(return_address)

    def va_args(self, index):
        print self.state
