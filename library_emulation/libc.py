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

import functools
from termcolor import colored

from smt import boolean as bl
from smt import bitvector as bv

from concolica.utils import *


# stdio.h

def fflush(s, cc):
    f = cc(s)

    stream = f.params[0]

    print('{} {} fflush(stream={});'.format(
        s.id, f.return_address(), stream))

    return f.ret(value=0)


def fopen(s, cc):
    f = cc(s)

    # TODO: can we control path

    path = f.params[0]
    mode = f.params[1]

    o = DummyOutputBuffer()
    o.append_string(String(s, path))
    path = o.string[:-1]

    o = DummyOutputBuffer()
    o.append_string(String(s, mode))
    mode = o.string

    file_id = len(s.files)

    print('{} {} fopen(path="{}", mode="{}"); [{}]'.format(
        s.id, f.return_address(), path, mode, file_id))

    s.files.append({
        'path':path,
        'mode':mode,
        'offset':0,
        'bytes':[]
    })

    return f.ret(value=file_id)


def fread(s, cc):
    f = cc(s)

    buf = f.params[0]
    size = f.params[1]
    count = f.params[2]
    stream = f.params[3]

    print('{} {} fread(ptr={}, size={}, count={}, stream={});'.format(
        s.id, f.return_address(), buf, size, count, stream))

    if stream.symbolic:
        raise ValueError('wtf')

    if stream.value > len(s.files):
        return f.ret(value=0)
    else:
        file = s.files[stream.value]
        offset = file['offset']
        output = OutputBuffer(s, buf)

        fd = None
        if file['path'] not in ['stdin', 'stdout', 'stderr']:
            fd = open(file['path'], 'rb')

        if size.symbolic or count.symbolic:
            raise NotImplementedError()
        elif fd is None:
            for i in range(0, size.value * count.value):
                output.append(bv.Symbol(8, 'file_{}_{:x}'.format(stream.value, offset)))
                offset += 1
        else:
            fd.seek(offset, 0)
            for i in range(0, size.value * count.value):
                byte = fd.read(1)
                if len(byte) == 1:
                    if byte == '#':
                        output.append(bv.Symbol(8, 'file_{}_{:x}'.format(stream.value, offset)))
                    else:
                        output.append(bv.Constant(8, ord(byte)))
                    offset += 1
                else:
                    break

        file['offset'] = offset

        if fd is not None:
            fd.close()

    return f.ret(value=output.index)


def fseek(s, cc):
    f = cc(s)

    stream = f.params[0]
    offset = f.params[1]
    origin = f.params[2]

    if origin.value == 0:
        origin = 'SEEK_SET'
    elif origin.value == 1:
        origin = 'SEEK_CUR'
    elif origin.value == 2:
        origin = 'SEEK_END'
    elif origin.value == 3:
        origin = 'SEEK_DATA'
    elif origin.value == 4:
        origin = 'SEEK_HOLE'

    print('{} {} fseek(stream={}, offset={}, origin={});'.format(
        s.id, f.return_address(), stream, offset, origin))

    return f.ret(value=0)


def gets(s, cc):
    f = cc(s)

    buf = f.params[0]

    print('{} {} gets(buf={});'.format(
        s.id, f.return_address(), buf))

    output = OutputBuffer(s, buf)

    for i in range(0, 0x1000):
        byte = bv.Symbol(8, unique_name('stdin_{0}'.format(i)))
        s.files[0]['bytes'].append(byte)
        output.append(byte)

    s.files[0]['bytes'].append(bv.Constant(8, 0x0a))
    output.append(bv.Constant(8, 0))

    return f.ret(value=buf)


def printf(s, cc):
    f = cc(s)

    fmt = f.params[0]
    va_args = f.va_args(1)

    print('{} {} printf(fmt={}, ...);'.format(
        s.id, f.return_address(), fmt))

    output = DummyOutputBuffer()

    states, outputs = format_string(s, output, fmt, va_args)

    ss = []

    for s_, o in zip(states, outputs):
        output_string = o.string.strip('\r').strip('\n')
        print('{}: '.format(s.id) + colored(output_string, 'green'))

        f_ = cc(s_)
        ss += f_.ret(value=o.index)

    return ss


def puts(s, cc):
    f = cc(s)

    buf = f.params[0]

    print('{} {} puts(str={});'.format(
        s.id, f.return_address(), buf))

    output = DummyOutputBuffer()
    string = String(s, buf)

    output.append_string(string)
    output_string = output.string.strip('\r').strip('\n')
    print('{}: '.format(s.id) + colored(output_string, 'green'))

    return f.ret(value=1)


# stdlib.h
def calloc(s, cc):
    f = cc(s)

    size = f.params[0]
    count = f.params[1]

    if size.symbolic or count.symbolic:
        raise NotImplementedError()
    else:
        ptr = s.memory.allocate(s, size.value * count.value)
        zero = bv.Constant(8, 0)
        for i in range(0, size.value * count.value):
            s.memory.write_byte(s, ptr + i, zero)

    print('{} {} calloc(size={}, count={}); [{:x}]'.format(
        s.id, f.return_address(), size, count, ptr))

    return f.ret(value=ptr)


def exit(s, cc):
    f = cc(s)

    status = f.params[0]

    print('{} {} exit(status={})'.format(
        s.id, f.return_address(), status))

    return []


def free(s, cc):
    f = cc(s)

    ptr = f.params[0]

    if ptr.symbolic:
        raise NotImplementedError()
    else:
        s.memory.free(s, ptr.value)

    print('{} {} free(ptr={})'.format(
        s.id, f.return_address(), ptr))

    return f.ret(value=0)


def malloc(s, cc):
    f = cc(s)

    size = f.params[0]

    if size.symbolic:
        raise NotImplementedError()
    else:
        ptr = s.memory.allocate(s, size.value)

    print('{} {} malloc(size={}); [{:x}]'.format(
        s.id, f.return_address(), size, ptr))

    return f.ret(value=ptr)


# string.h

def memchr(s, cc):
    f = cc(s)

    ptr = f.params[0]
    value = f.params[1].resize(8)
    num = f.params[2]

    if num.symbolic:
        num = maximum(s, num)

    print('{} {} memchr(ptr={}, value={}, num={})'.format(
        s.id, f.return_address(), ptr, value, num))

    if ptr.symbolic:
        ptrs = concretise(s, ptr)
    else:
        ptrs = [ptr]

    ss = []
    total_ptrs = len(ptrs)
    while len(ptrs) > 0:
        ptr = ptrs.pop()

        if total_ptrs > 1:
            s_ = s.fork()
        else:
            s_ = s

        count = 0
        null = bv.Constant(ptr.size, 0)
        bytes = []

        not_terminated = None
        not_already_terminated = bl.Constant(True)
        while s_.solver.check(num > count):
            byte = s_.read(ptr + bv.Constant(ptr.size, count), 8)

            not_terminated = not_already_terminated & (byte == value)
            bytes.append((not_already_terminated, byte, count))

            if not_terminated.symbolic:
                not_already_terminated = bl.Symbol(unique_name('tmp'))
                s_.solver.add(not_already_terminated == not_terminated)
            else:
                not_already_terminated = not_terminated

            count += 1

        bytes.reverse()

        result = None
        prev_result = None
        for (not_already_terminated, byte, count) in bytes:
            if result is None:
                result = bv.if_then_else(
                            byte == value,
                            ptr + bv.Constant(ptr.size, count),
                            null)
            else:
                result = bv.if_then_else(
                            not_already_terminated,
                            bv.if_then_else(
                                byte == value,
                                ptr + bv.Constant(ptr.size, count),
                                prev_result),
                            prev_result)

            # this reduces the memory footprint_ of the resulting expression
            # significantly
            prev_result = bv.Symbol(ptr.size, unique_name('tmp'))
            s_.solver.add(prev_result == result)

        if result.symbolic:
            result_symbol = bv.Symbol(ptr.size, unique_name('memcmp'))
            s_.solver.add(result_symbol == result)
            result = result_symbol

        f_ = cc(s_)
        ss += f_.ret(value=result)

    return ss


def memcmp(s, cc):
    f = cc(s)

    ptr1 = f.params[0]
    ptr2 = f.params[1]
    num = f.params[2]

    print('{} {} memcmp(ptr1={}, ptr2={}, num={})'.format(
        s.id, f.return_address(), ptr1, ptr2, num))

    count = 0

    first_smaller = bv.Constant(ptr1.size, -1)
    first_larger = bv.Constant(ptr1.size, 1)
    zero = bv.Constant(ptr1.size, 0)

    bytes = []

    not_terminated = None
    not_already_terminated = bl.Constant(True)
    while s.solver.check(num > count):
        byte1 = s.read(ptr1 + bv.Constant(ptr1.size, count), 8)
        byte2 = s.read(ptr2 + bv.Constant(ptr2.size, count), 8)

        not_terminated = not_already_terminated & (byte1 == byte2)

        bytes.append((not_already_terminated, byte1, byte2))

        if not_terminated.symbolic:
            not_already_terminated = bl.Symbol(unique_name('tmp'))
            s.solver.add(not_already_terminated == not_terminated)
        else:
            not_already_terminated = not_terminated

        count += 1

    bytes.reverse()

    result = None
    prev_result = None
    for (not_already_terminated, byte1, byte2) in bytes:
        if result is None:
            result = bv.if_then_else(
                        byte1 == byte2,
                        zero,
                        bv.if_then_else(
                            byte1 < byte2,
                            first_smaller,
                            first_larger))
        else:
            result = bv.if_then_else(
                        not_already_terminated,
                        bv.if_then_else(
                            byte1 == byte2,
                            prev_result,
                            bv.if_then_else(
                                byte1 < byte2,
                                first_smaller,
                                first_larger)),
                        prev_result)

        # this reduces the memory footprint_ of the resulting expression
        # significantly
        prev_result = bv.Symbol(ptr1.size, unique_name('tmp'))
        s.solver.add(prev_result == result)

    if result.symbolic:
        result_symbol = bv.Symbol(result.size, unique_name('memcmp'))
        s.solver.add(result_symbol == result)
        result = result_symbol

    return f.ret(value=result)


def register_hooks(s, cc):
    h = s.function_hooks

    def register_hook(name, hook):
        h[name] = functools.partial(hook, cc=cc)

    # stdio.h
    register_hook('fflush', fflush)
    register_hook('fopen', fopen)
    register_hook('fread', fread)
    register_hook('fseek', fseek)
    register_hook('gets', gets)
    register_hook('printf', printf)
    register_hook('puts', puts)

    # stdlib.h
    register_hook('calloc', calloc)
    register_hook('exit', exit)
    register_hook('free', free)
    register_hook('malloc', malloc)

    # string.h
    register_hook('memchr', memchr)
    register_hook('memcmp', memcmp)
    register_hook('__memcmp_sse4_1', memcmp)