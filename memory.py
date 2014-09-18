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


from smt import bitvector as bv
from smt import boolean as bl

from concolica.utils import *
from concolica.vulnerabilities import *


class StaticMemory(object):
    """
    Global static memory, used for static buffers such as the sections of a
    loaded binary in memory, or the initial mappings when loading a process
    directly from a debugger session
    """

    __slots__ = ('_cache', '_depth', '_pages')

    def __init__(self):
        self._cache = dict()
        self._pages = []


    def add_mapping(self, base, data):
        limit = base + len(data)
        for b, l, d in self._pages:
            if b <= base < l:
                print 'overlapping static mapping at {:x}'.format(base)
            elif base <= b < limit:
                print 'overlapping static mapping at {:x}'.format(base)

        self._pages.append((base, limit, data))


    def is_mapped(self, state, address):

        for b, l, d in self._pages:
            if b <= address < l:
                return True

        return False


    def read_byte(self, state, address):

        try:
            return self._cache[address]

        except KeyError:
            for b, l, d in self._pages:
                if b <= address < l:
                    value = bv.Constant(8, ord(d[address - b]))
                    self._cache[address] = value
                    return value

        state.throw(InvalidRead(state, address))


class DynamicMemory(object):
    """
    Per-state dynamic memory object; this is what's used to back all
    memory written to during emulation.
    """

    __slots__ = ('_cache', '_parent')


    def __init__(self, parent):
        self._cache = dict()
        self._parent = parent
        if self.depth() > 8:
            self.flatten()


    def __getstate__(self):
        self.flatten()
        return (self._cache, self._parent)


    def __setstate__(self, dict):
        self._cache = dict[0]
        self._parent = dict[1]


    def depth(self):
        d = 0
        p = self._parent

        while not isinstance(p, StaticMemory):
            d += 1
            p = p._parent

        return d


    def flatten(self):
        cs = []
        p = self._parent

        while not isinstance(p, StaticMemory):
            cs.append(p._cache)
            p = p._parent

        cs.reverse()

        for c in cs:
            self._cache.update(c)

        self._parent = p


    def is_mapped(self, state, address):

        if address in self._cache:
            return True

        else:
            return self._parent.is_mapped(state, address)


    def read_byte(self, state, address):

        try:
            return self._cache[address]

        except KeyError:
            return self._parent.read_byte(state, address)


    def write_byte(self, state, address, value):

        if self.is_mapped(state, address):
            self._cache[address] = value

        else:
            state.throw(InvalidWrite(state, address, value))