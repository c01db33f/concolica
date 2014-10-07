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


import copy
import re

from concolica import log
from concolica import memory
from concolica.utils import *
from concolica.vulnerabilities import *

import reil

import smt
import smt.bitvector as bv


class Registers(dict):

    __slots__ = ('_registers', '_parent')

    def __init__(self, parent=None):
        dict.__init__(self)
        self._parent = parent
        if self.depth() > 2:
            self.flatten()

    def dirty(self):
        return self.depth() == 0 or len(self) > 0

    def __getstate__(self):
        self.flatten()
        return dict(self)

    def __setstate__(self, d):
        self.update(d)
        self._parent = None

    def __contains__(self, item):
        if dict.__contains__(self, item):
            return True

        if self._parent is not None:
            return item in self._parent

        return False

    def __missing__(self, key):
        if self._parent is None:
            raise KeyError()

        return self._parent[key]

    def clear_il_state(self):

        # TODO: this is *insanely* lazy and inefficient

        il_register_re = re.compile('^t\d+$')
        for r in self.keys():
            if il_register_re.match(r):
                del self[r]

    def depth(self):
        d = 0
        p = self._parent

        while p is not None:
            d += 1
            p = p._parent

        return d

    def flatten(self):
        cs = []
        p = self._parent

        while p is not None:
            cs.append(p)
            p = p._parent

        cs.reverse()

        for c in cs:
            self.update(c)

        self._parent = p


class State(object):

    _state_id = interlocked.Counter()

    def __init__(self, parent=None):
        self.id = 0
        self.parent = parent
        self.score = 0

        self.log = log.StateLogger(self)

        if parent:
            self.ip = parent.ip
            self.il_index = parent.il_index

            self.memory = memory.DynamicMemory(parent.memory)
            self.registers = Registers(parent.registers)
            self.call_stack = copy.copy(parent.call_stack)

            self.function_hooks = parent.function_hooks
            self.kernel = parent.kernel
            self.symbols = parent.symbols

            self.solver = smt.Solver(parent.solver)
            self.files = copy.deepcopy(parent.files)
            self.trace = list(parent.trace)
        else:
            self.ip = 0
            self.il_index = 0

            self.memory = None
            self.registers = Registers()
            self.call_stack = []

            self.function_hooks = dict()
            self.kernel = None
            self.symbols = dict()

            self.symbols = None
            self.solver = smt.Solver()
            self.files = [
                {
                    'path':   'stdin',
                    'mode':   'r',
                    'offset': 0,
                    'bytes':  dict()
                },
                {
                    'path':   'stdout',
                    'mode':   'w',
                    'offset': 0,
                    'bytes':  dict()
                },
                {
                    'path':   'stderr',
                    'mode':   'w',
                    'offset': 0,
                    'bytes':  dict()
                }]
            self.trace = []

    def __getstate__(self):
        l = None
        try:
            l = self.log
            self.log = None
            return dict(self.__dict__)
        finally:
            self.log = l

    def __setstate__(self, d):
        self.__dict__ = d
        self.log = log.StateLogger(self)

    def clear_il_state(self):
        self.registers.clear_il_state()
        self.il_index = 0

    def fork(self):
        new = State(self)
        #if self.id == 0:
        new.id = State._state_id.increment()
        self.log.fork(new.id)
        #else:
        #    new.id = self.id
        #    self.id = 0

        return new

    def read(self, address, size):
        if arbitrary(self, address):
            raise ArbitraryRead(self, address)

        as_ = concretise(self, address)
        try:
            if len(as_) > 1:
                e = None
                value = bv.Symbol(size, unique_name('read'))

                for a in as_:
                    v = None
                    for i in range(0, size // 8):
                        if v is None:
                            v = self.memory.read_byte(self, a.value + i)
                        else:
                            v = self.memory.read_byte(self, a.value + i).concatenate(v)

                    if e is None:
                        e = (address == a) & (value == v)
                    else:
                        e = e | ((address == a) & (value == v))

                self.solver.add(e)
            else:
                value = self.memory.read_byte(self, as_[0].value)

                for i in range(1, size // 8):
                    value = self.memory.read_byte(self, as_[0].value + i).concatenate(value)
        except KeyError:
            raise InvalidRead(self, address)

        return value

    def write(self, address, value):
        bs = []
        for i in range(0, value.size, 8):
            bs.append(value.extract(start=i, end=i + 8))
        bs.reverse()

        if arbitrary(self, address):
            raise ArbitraryWrite(self, address, value)

        as_ = concretise(self, address)
        if len(as_) > 1:
            for a in as_:
                for i, byte in enumerate(bs):
                    self.memory.write_byte(self, a.value + i, smt.bv.IfThenElse(
                        a != address,
                        self.memory.read_byte(self, a.value + i),
                        byte))
        else:
            for i, byte in enumerate(bs):
                self.memory.write_byte(self, as_[0].value + i, byte)

    def branch(self, address):
        ss = []
        if isinstance(address, reil.OffsetOperand):
            self.il_index = address.offset
            ss.append(self)
        else:
            #sp =

            self.il_index = 0xfffffff
            if address.symbolic:
                if arbitrary(self, address):
                    raise ArbitraryExecution(self, address)
                else:
                    ss = []
                    as_ = concretise(self, address)
                    if len(as_) > 1:
                        for a in as_:
                            b = self.fork()
                            b.ip = a.value
                            ss.append(b)
                    else:
                        self.ip = as_[0].value
                        ss.append(self)
            else:
                self.ip = address.value
                ss.append(self)

        return ss

    def throw(self, exception):
        raise exception