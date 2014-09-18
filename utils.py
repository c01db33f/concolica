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

from concolica import interlocked


name_index = interlocked.Counter()
def unique_name(name):
    return '{0}_{1:x}'.format(name, name_index.increment())


def mask(size):
    """The basic bitmask to extract the value of bit-size 'size'."""

    if size == 8:
        return 0xff
    elif size == 16:
        return 0xffff
    elif size == 32:
        return 0xffffffff
    elif size == 64:
        return 0xffffffffffffffff
    elif size == 128:
        return 0xffffffffffffffffffffffffffffffff


def concretise(state, value, count=8):
    values = set()
    constraint = None

    if not value.symbolic:
        return [value]
    elif not isinstance(value, bv.Symbol):
        new_value = bv.Symbol(value.size, unique_name('concretise'))
        constraint = (new_value == value)
        state.solver.add(constraint)
        value = new_value
    
    # we now know that value is a symbol
    
    # TODO: this really hurts performance, but it will probably also help
    # with finding bugs... add in again once I have better path culling
    # heuristics again
    
    #values.add(maximum(state, value))
    #values.add(minimum(state, value))

    #if len(values) == 1:
        # max == min, our work here is done...
    #    return list(values)

    while len(values) < count:
        if not state.solver.check(constraint):
            break
        
        m = state.solver.model(constraint)
        if value.name not in m:
            # solver doesn't know anything about our value yet...
            constraint = value != 0xbeefcafe
            continue
        
        model_value = m[value.name]
        values.add(model_value)
        
        if constraint is not None:
            constraint = bl.BinaryOperation(
                constraint,
                bl.BinaryOperator.And,
                value != model_value)
        else:
            constraint = value != model_value

    #print list(map(lambda x:hex(x.value), values))

    return list(values)


def minimum(state, value):
    if not value.symbolic:
        return value
    
    absolute_max = -1 & mask(value.size)
    lower = 0
    upper = absolute_max
    
    while (upper - lower) > 1:
        mid = (upper + lower) // 2
        if state.solver.check(value < bv.Constant(value.size, mid)):
            upper = mid
        else:
            lower = mid

    return bv.Constant(value.size, lower)


def maximum(state, value):
    if not value.symbolic:
        return value
    
    absolute_max = -1 & mask(value.size)
    lower = 0
    upper = absolute_max
    
    while (upper - lower) > 1:
        mid = (upper + lower) // 2
        if state.solver.check(value > bv.Constant(value.size, mid)):
            lower = mid
        else:
            upper = mid

    return bv.Constant(value.size, upper)


def arbitrary(state, value):
    if state.solver.check(value == bv.Constant(value.size, 0xc01db33f)):
        return True
    return False


class String(object):

    def __init__(self, state, address):
        self.state = state
        self.address = address

    def __iter__(self):
        terminated = False
        index = 0
        constraint = bl.Constant(True)
        while not terminated:
            read_address = self.address + bv.Constant(self.address.size, index)
            byte = self.state.read(read_address, 8)

            if self.state.solver.check(byte.can_be_nonzero()):
                if byte.symbolic:
                    if not constraint.symbolic:
                        constraint = (byte != 0)
                    else:
                        constraint = constraint & (byte != 0)

                    # this might look silly, but it actually makes the
                    # output smt formulae substantially smaller...

                    returned_constraint = bl.Symbol(unique_name('string_length'))
                    self.state.solver.add(returned_constraint == constraint)
                    yield (byte, returned_constraint)
                else:
                    yield (byte, constraint)
            else:
                terminated = True
                yield (bv.Constant(8, 0), constraint)
            index += 1


class OutputBuffer(object):


    def __init__(self, state, address):
        self.state = state
        self.address = address
        self.index = 0


    def copy(self, new_state):
        new = OutputBuffer(new_state, self.address)
        new.index = self.index
        return new


    def append(self, c):
        if isinstance(c, str):
            c = bv.Constant(8, ord(c))

        write_address = self.address + bv.Constant(self.address.size, self.index)
        self.index += 1
        self.state.write(write_address, c)


    def append_string(self, s, max_len=None):
        if max_len is not None:
            if isinstance(s, str):
                l = 0
                for c in s:
                    if l > max_len:
                        break
                    self.append(c)
                    l += 1
            elif isinstance(s, String):
                l = 0
                for c, constraint in s:
                    if l > max_len:
                        break
                    self.append(c)
                    l += 1
            else:
                raise 'not supported this yet, whatever this is'
        else:
            if isinstance(s, str):
                for c in s:
                    self.append(c)
            elif isinstance(s, String):
                for c, constraint in s:
                    self.append(c)
            else:
                raise 'not supported this yet, whatever this is'


class BoundOutputBuffer(OutputBuffer):

    def __init__(self, state, address, length):
        OutputBuffer.__init__(self, state, address)
        if isinstance(length, int):
            self.length = length
        else:
            self.length = length.value

    def copy(self, new_state):
        new = BoundOutputBuffer(new_state, self.address, self.length)
        new.index = self.index
        return new

    def append(self, c):
        if self.index < self.length:
            OutputBuffer.append(self, c)


class DummyOutputBuffer(OutputBuffer):

    def __init__(self):
        self.string = ''
        self.index = 0

    def copy(self, new_state):
        new = DummyOutputBuffer()
        new.string = str(self.string)
        new.index = self.index
        return new

    def append(self, c):
        if isinstance(c, str):
            self.string += c
        elif c.symbolic:
            self.string += '?'
        else:
            self.string += chr(c.value)
        self.index += 1


def concrete_format_string(state, output, fmt, va_args):
    percent = False
    zero_fill = False
    left_align = False
    width = ''

    arg_index = 0

    states = [state]
    outputs = [output]
    for char, constraint in String(state, fmt):
        if char.symbolic:
            # we don't handle symbolic input strings, except to attempt
            # to insert a %n
            if not percent:
                if state.solver.check(constraint & (char == ord('%'))):
                    percent = True
                else:
                    output.append('?')
            else:
                if state.solver.check(constraint & (char == ord('n'))):
                    raise 'boomerlolwtfformatpwned'
                output.append('?')
        else:
            # here is the meat of it
            c = chr(char.value)
            #print(c)

            # if we're not in a format specification
            if not percent:
                if c == '%':
                    percent = True
                else:
                    output.append(c)

            # we're in a format specification
            else:
                output_strings = []
                output_constraints = []

                if c == '%':
                    output_string = '%'
                elif c == 'c':
                    # print a single character
                    value = va_args[arg_index].resize(8)
                    if value.symbolic:
                        output_strings.append('?')
                    else:
                        output_strings.append('{0}'.format(chr(value.value)))
                elif c == 'd':
                    # print a decimal number
                    value = va_args[arg_index]
                    if value.symbolic:
                        output_strings.append('?')
                    else:
                        output_strings.append('{0:d}'.format(value.value))
                elif c == 'i':
                    # print an integer
                    value = va_args[arg_index]
                    if value.symbolic:
                        output_strings.append('?')
                    else:
                        output_strings.append('{0:d}'.format(value.value))
                elif c == 'n':
                    # writeback current chars written
                    output_strings.append('n_not_supported')
                elif c == 'o':
                    # print integer in octal
                    output_strings.append('o_not_supported')
                elif c == 's':
                    # print a string
                    strptr = va_args[arg_index]
                    if strptr.symbolic:
                        # oh fuck me sideways
                        for ptr in concretise(state, strptr):
                            s = String(state, ptr)
                            tmp = DummyOutputBuffer()
                            tmp.append_string(s)
                            output_strings.append(tmp.string)
                            output_constraints.append(strptr == ptr)
                    else:
                        s = String(state, strptr)
                        tmp = DummyOutputBuffer()
                        tmp.append_string(s)
                        output_strings.append(tmp.string)
                elif c == 'u':
                    # print an unsigned integer
                    output_strings.append('u_not_supported')
                elif c == 'x':
                    # print integer in hexadecimal
                    value = va_args[arg_index]
                    if value.symbolic:
                        output_strings.append('?')
                    else:
                        output_strings.append('{0:x}'.format(value.value))
                elif c in '123456789':
                    width += c
                elif c == '0':
                    zero_fill = True
                elif c == '-':
                    left_align = True
                else:
                    # skip unrecongised characters
                    pass


                def _format_output_string(string, width, zero_fill, left_align):
                    if len(width) > 0:
                        width = int(width)
                        while len(string) < int(width):
                            if zero_fill:
                                string = '0' + string
                            elif left_align:
                                string = string + ' '
                            else:
                                string = ' ' + string
                    return string

                import functools

                format_output_string = functools.partial(
                    _format_output_string,
                    width=width,
                    zero_fill=zero_fill,
                    left_align=left_align)

                if len(output_strings) > 1:
                    output_strings = list(map(format_output_string, output_strings))

                    # we need to make a copy here as we're going
                    # to be modifying these lists
                    for s, o in list(zip(states, outputs)):
                        for i, output_string in enumerate(output_strings):
                            if i != len(output_strings) - 1:
                                new_s = s.fork()
                                new_o = o.copy(new_s)
                                states.append(new_s)
                                new_s.solver.add(output_constraints[i])
                                new_o.append_string(output_string)
                                outputs.append(new_o)
                            else:
                                s.solver.add(output_constraints[i])
                                o.append_string(output_string)

                    percent = False
                    zero_fill = False
                    left_align = False
                    arg_index += 1

                elif len(output_strings) == 1:
                    output_string = format_output_string(output_strings[0])

                    for output in outputs:
                        output.append_string(output_string)

                    percent = False
                    zero_fill = False
                    left_align = False
                    arg_index += 1

    return states, outputs


def format_string(s, output, fmt, var_args):
    if fmt.symbolic:
        fmts = concretise(s, fmt)
    else:
        fmts = [fmt]

    ss = []
    os = []

    total_fmts = len(fmts)
    while len(fmts):
        f_ = fmts.pop()

        if total_fmts > 1:
            s_ = s.fork()
            o_ = output.copy(s)
            v_ = var_args.copy(s)
        else:
            s_ = s
            o_ = output
            v_ = var_args

        ns, no = concrete_format_string(s_, o_, f_, v_)

        ss += ns
        os += no

    return ss, os