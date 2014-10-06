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


# err.h

def err(s, cc):
    f = cc(s)

    eval = f.params[0]
    fmt = f.params[1]
    va_args = f.va_args(2)

    s.log.function_call(f, 'err(eval={}, fmt={})', eval, fmt)

    output = DummyOutputBuffer()

    states, outputs = format_string(s, output, fmt, va_args)

    ss = []

    for s_, o in zip(states, outputs):
        output_string = o.string.strip('\r').strip('\n')
        s_.log.output(output_string)

    return []


def errx(s, cc):
    f = cc(s)

    eval = f.params[0]
    fmt = f.params[1]
    va_args = f.va_args(2)

    s.log.function_call(f, 'errx(eval={}, fmt={})', eval, fmt)

    output = DummyOutputBuffer()

    states, outputs = format_string(s, output, fmt, va_args)

    ss = []

    for s_, o in zip(states, outputs):
        output_string = o.string.strip('\r').strip('\n')
        s_.log.output(output_string)

    return []


def warn(s, cc):
    f = cc(s)

    fmt = f.params[0]
    va_args = f.va_args(1)

    s.log.function_call(f, 'warn(fmt={})', fmt)

    output = DummyOutputBuffer()

    states, outputs = format_string(s, output, fmt, va_args)

    ss = []

    for s_, o in zip(states, outputs):
        output_string = o.string.strip('\r').strip('\n')
        s_.log.output(output_string)

    return []


def warnx(s, cc):
    f = cc(s)

    fmt = f.params[0]
    va_args = f.va_args(1)

    s.log.function_call(f, 'warnx(fmt={})', fmt)

    output = DummyOutputBuffer()

    states, outputs = format_string(s, output, fmt, va_args)

    ss = []

    for s_, o in zip(states, outputs):
        output_string = o.string.strip('\r').strip('\n')
        s_.log.output(output_string)

    return []


# stdio.h

def fflush(s, cc):
    f = cc(s)

    stream = f.params[0]

    s.log.function_call(f, 'fflush(stream={})', stream)

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

    s.log.function_call(f, 'fopen(path="{}", mode="{}") [{}]', path, mode, file_id)

    s.files.append({
        'path':path,
        'mode':mode,
        'offset':0,
        'bytes':dict()
    })

    return f.ret(value=file_id)


def fread(s, cc):
    f = cc(s)

    buf = f.params[0]
    size = f.params[1]
    count = f.params[2]
    stream = f.params[3]

    s.log.function_call(f, 'fread(ptr={}, size={}, count={}, stream={})', buf, size, count, stream)

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
            for i in xrange(0, size.value * count.value):
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

    s.log.function_call(f, 'fseek(stream={}, offset={}, origin={})', stream, offset, origin)

    return f.ret(value=0)


def gets(s, cc):
    f = cc(s)

    buf = f.params[0]


    s.log.function_call(f, 'gets(buf={})', buf)

    output = OutputBuffer(s, buf)

    # TODO: this needs to use the file for stdin instead of this nonsense

    for i in xrange(0, 0x100000):
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

    s.log.function_call(f, 'printf(fmt={}, ...)', fmt)

    output = DummyOutputBuffer()

    states, outputs = format_string(s, output, fmt, va_args)

    ss = []

    for s_, o in zip(states, outputs):
        output_string = o.string.strip('\r').strip('\n')
        s_.log.output(output_string)

        f_ = cc(s_)
        ss += f_.ret(value=o.index)

    return ss


def puts(s, cc):
    f = cc(s)

    buf = f.params[0]

    s.log.function_call(f, 'puts(str={})', buf)

    output = DummyOutputBuffer()
    string = String(s, buf)

    output.append_string(string)
    output_string = output.string.strip('\r').strip('\n')
    s.log.output(output_string)

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
        for i in xrange(0, size.value * count.value):
            s.memory.write_byte(s, ptr + i, zero)

    s.log.function_call(f, 'calloc(size={}, count={}) [{:x}]', size, count, ptr)

    return f.ret(value=ptr)


def exit(s, cc):
    f = cc(s)

    status = f.params[0]

    s.log.function_call(f, 'exit(status={})', status)

    return []


def free(s, cc):
    f = cc(s)

    ptr = f.params[0]

    if ptr.symbolic:
        raise NotImplementedError()
    else:
        s.memory.free(s, ptr.value)

    s.log.function_call(f, 'free(ptr={})', ptr)

    return f.ret(value=0)


def malloc(s, cc):
    f = cc(s)

    size = f.params[0]

    ss = []
    sizes = []
    if size.symbolic:
        min_size = minimum(s, size)
        max_size = maximum(s, size)

        sizes.append(min_size.value)

        if min_size != max_size:
            sizes.append(max_size.value)
    else:
        sizes.append(size.value)

    ss = []
    total_sizes = len(sizes)
    while len(sizes) > 0:
        size_ = sizes.pop()

        if total_sizes > 1:
            s_ = s.fork()
        else:
            s_ = s

        s_.solver.add(size == bv.Constant(size.size, size_))
        ptr = s_.memory.allocate(s_, size_)

        f_ = cc(s_)
        ss += f_.ret(value=ptr)

        s_.log.function_call(f, 'malloc(size={}) [{:x}]', size_, ptr)

    return ss


def realloc(s, cc):
    f = cc(s)

    ptr = f.params[0]
    size = f.params[1]

    if ptr.symbolic:
        raise NotImplementedError()

    ss = []
    sizes = []
    if size.symbolic:
        min_size = minimum(s, size)
        max_size = maximum(s, size)

        sizes.append(min_size.value)

        if min_size != max_size:
            sizes.append(max_size.value)
    else:
        sizes.append(size.value)

    ss = []
    total_sizes = len(sizes)
    while len(sizes) > 0:
        size_ = sizes.pop()

        if total_sizes > 1:
            s_ = s.fork()
        else:
            s_ = s

        s_.solver.add(size == bv.Constant(size.size, size_))
        ptr_ = s_.memory.reallocate(s_, ptr.value, size_)

        f_ = cc(s_)
        ss += f_.ret(value=ptr_)

        s_.log.function_call(f, 'realloc(ptr={}, size={}) [{:x}]', ptr, size_, ptr_)

    return ss


# string.h

def memchr(s, cc):
    f = cc(s)

    ptr = f.params[0]
    value = f.params[1].resize(8)
    num = f.params[2]

    if num.symbolic:
        num = maximum(s, num)

    s.log.function_call(f, 'memchr(ptr={}, value={}, num={})', ptr, value, num)

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

    s.log.function_call(f, 'memcmp(ptr1={}, ptr2={}, num={})', ptr1, ptr2, num)

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


def memset(s, cc):
    f = cc(s)

    dst = f.params[0]
    val = f.params[1].resize(8)
    count = f.params[2]

    output = OutputBuffer(s, dst)

    if count.symbolic:
        count = maximum(s, count)

    s.log.function_call(f, 'memset(dst={}, val={}, count={})', dst, val, count)

    for i in xrange(0, count.value):
        output.append(val)

    return f.ret()


def strcmp(s, cc):
    f = cc(s)

    str1 = f.params[0]
    str2 = f.params[1]

    s.log.function_call(f, 'strcmp(str1={}, str2={})', str1, str2)

    iter1 = iter(String(s, str1))
    iter2 = iter(String(s, str2))

    first_smaller = bv.Constant(32, -1)
    first_larger = bv.Constant(32, 1)
    zero = bv.Constant(32, 0)

    characters = []
    not_terminated = None
    not_already_terminated = bl.Constant(True)
    while True:
        (char1, constraint1) = next(iter1)
        (char2, constraint2) = next(iter2)

        not_terminated = not_already_terminated & constraint1
        not_terminated = not_terminated & constraint2
        not_terminated = not_terminated & (char1 == char2)

        characters.append((not_already_terminated, char1, char2))

        not_already_terminated = not_terminated

        if ((not char1.symbolic and char1.value == 0)
            or (not char2.symbolic and char2.value == 0)):
            break

    characters.reverse()

    result = None
    prev_result = None
    for (not_already_terminated, char1, char2) in characters:
        if result is None:
            result = bv.if_then_else(
                        char1 == char2,
                        zero,
                        bv.if_then_else(
                            char1 < char2,
                            first_smaller,
                            first_larger))
        else:
            result = bv.if_then_else(
                        not_already_terminated,
                        bv.if_then_else(
                            char1 == char2,
                            prev_result,
                            bv.if_then_else(
                                char1 < char2,
                                first_smaller,
                                first_larger)),
                        prev_result)

        # this reduces the memory footprint_ of the resulting expression
        # significantly
        prev_result = bv.Symbol(32, unique_name('tmp'))
        s.solver.add(prev_result == result)

    if result.symbolic:
        result_symbol = bv.Symbol(32, unique_name('strcmp'))
        s.solver.add(result_symbol == result)
        result = result_symbol

    return f.ret(value=result)


def register_hooks(s, cc):
    h = s.function_hooks

    def register_hook(name, hook):
        h[name] = functools.partial(hook, cc=cc)

    # err.h
    register_hook('err', err)
    register_hook('errx', errx)
    register_hook('warn', warn)
    register_hook('warnx', warnx)

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
    register_hook('realloc', realloc)

    # string.h
    register_hook('memchr', memchr)
    register_hook('memcmp', memcmp)
    register_hook('memset', memset)
    register_hook('strcmp', strcmp)
    register_hook('__memcmp_sse4_1', memcmp)
    register_hook('__strcmp_ssse3', strcmp)