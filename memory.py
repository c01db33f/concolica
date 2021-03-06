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


from rbtree import rbtree


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

    __slots__ = ('_bulk_set', '_cache', '_parent', '_heap_next', '_heap_blocks', '_heap_free')

    def __init__(self, parent):
        self._bulk_set = []
        self._cache = rbtree()
        self._parent = parent

        if isinstance(parent, StaticMemory):
            self._heap_next = 0x00007ffff7f93000#0x80000000
            self._heap_blocks = dict()
            self._heap_free = dict()
        else:
            self._heap_next = parent._heap_next
            self._heap_blocks = dict(parent._heap_blocks)
            self._heap_free = dict(parent._heap_free)

        if self.depth() > 8:
            self.flatten()

    def dirty(self):
        return self.depth() == 0 or len(self._cache) > 0

    def __getstate__(self):
        self.flatten()
        return dict(self._cache), self._parent, self._heap_next, self._heap_blocks, self._heap_free

    def __setstate__(self, d):
        self._cache = rbtree(d[0])
        self._parent = d[1]
        self._heap_next = d[2]
        self._heap_blocks = d[3]
        self._heap_free = d[4]

    def allocate(self, state, size):

        # TODO: we need to write in 'uninitialised memory blocks'
        # this way we can distinguish boring and interesting use
        # of uninitialised heap

        ptr = self._heap_next
        self._heap_blocks[ptr] = size
        self._heap_next += ((size // 0x1000) + 1) * 0x1000
        return ptr

    def free(self, state, ptr):
        size = self._heap_blocks[ptr]

        # clear any local cache values
        tmp = self._cache[:ptr]
        self._cache = self._cache[ptr + size:]
        self._cache.update(tmp)

        self._heap_free[ptr] = size
        del self._heap_blocks[ptr]

    def reallocate(self, state, ptr, size):
        old_size = self._heap_blocks[ptr]
        new_ptr = self.allocate(state, size)
        for i in range(0, min(old_size, size)):
            self.write_byte(state, new_ptr + i, self.read_byte(state, ptr + i))

        self.free(state, ptr)
        return new_ptr

    def bulk_set(self, state, ptr, count, value):
        # don't bother for small blocks
        if count < 128:
            for i in xrange(ptr, ptr + count):
                self.write_byte(state, ptr, value)
        else:
            # perfunctory check; anything else is too slow
            if not self.is_mapped(state, ptr):
                raise InvalidWrite(state, ptr, value)
            if not self.is_mapped(state, ptr + count - 1):
                raise InvalidWrite(state, ptr + count - 1, value)

            # clear any local cache values
            tmp = self._cache[:ptr]
            self._cache = self._cache[ptr + count:]
            self._cache.update(tmp)

            self._bulk_set.append((ptr, ptr + count - 1, value))

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

        for block in self._heap_blocks:
            if block <= address < block + self._heap_blocks[block]:
                return True

        return self._parent.is_mapped(state, address)

    def read_byte(self, state, address):
        try:
            return self._cache[address]
        except KeyError:

            # check if it's been freed
            for block in self._heap_free:
                if block <= address < block + self._heap_free[block]:
                    raise UseAfterFree(state, address)

            # check if it's been memset
            for base, limit, value in self._bulk_set:
                if base <= address <= limit:
                    return value

            return self._parent.read_byte(state, address)

    def write_byte(self, state, address, value):
        if self.is_mapped(state, address):
            self._cache[address] = value
        else:
            state.throw(InvalidWrite(state, address, value))