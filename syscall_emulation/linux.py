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

from smt import bitvector as bv

from concolica.utils import *

def sys_brk(s, cc):
    f = cc(s)

    brk = f.params[0]

    print('{} {} sys_brk({})'.format(
        s.id, f.return_address(), brk))

    if brk.value == 0:
        ptr = s.memory.allocate(bv.Constant(32, 0x10000))

    return f.ret(value=ptr)


def sys_chdir(s, cc):
    f = cc(s)

    filename = f.params[0]

    o = DummyOutputBuffer()
    o.append_string(String(s, filename))
    filename = o.string

    print('{} {} sys_chdir({})'.format(
        s.id, f.return_address(), filename))

    return f.ret(value='sys_chdir')


def sys_exit(s, cc):
    f = cc(s)

    arg0 = f.params[0]

    print('{} {} sys_exit({})'.format(s.id, f.return_address(), arg0))

    return []


def sys_exit_group(s, cc):
    f = cc(s)

    arg0 = f.params[0]

    print('{} {} sys_exit_group({})'.format(s.id, f.return_address(), arg0))

    return []


def sys_fstat(s, cc):
    f = cc(s)

    fd = f.params[0]
    statbuf = f.params[1]

    print('{} {} sys_fstat(fd={}, statbuf={})'.format(
        s.id, f.return_address(), fd, statbuf))

    o = OutputBuffer(s, statbuf)
    for i in range(0, 64): # sizeof(struct stat) == 64
        o.append(bv.Symbol(8, unique_name('fstat')))

    return f.ret(value=0)


def sys_fstat64(s, cc):
    f = cc(s)

    fd = f.params[0]
    statbuf = f.params[1]

    print('{} {} sys_fstat64(fd={}, statbuf={})'.format(
        s.id, f.return_address(), fd, statbuf))

    o = OutputBuffer(s, statbuf)
    if not fd.symbolic and fd.value == 1:
        for c in '\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x90\x21\x00\x00\x01\x00\x00\x00\xe8\x03\x00\x00\x05\x00\x00\x00\x03\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50\x5d\x08\x54\x3d\xa7\x22\x1b\x50\x5d\x08\x54\x3d\xa7\x22\x1b\x43\x40\x08\x54\x3d\xa7\x22\x1b\x06\x00\x00\x00\x00\x00\x00\x00':
            o.append(c)
    else:
        for i in range(0, 96): # sizeof(struct stat64) == 96
            o.append(bv.Symbol(8, unique_name('fstat64')))

    return f.ret(value=0)


def sys_futex(s, cc):
    f = cc(s)

    uaddr = f.params[0]
    op = f.params[1]
    val = f.params[2]
    utime = f.params[3]
    uaddr2 = f.params[4]

    print('{} {} sys_futex(uaddr={}, op={}, val={}, utime={}, uaddr2={})'.format(
        s.id, f.return_address(), uaddr, op, val, utime, uaddr2))

    return f.ret(value='sys_futex')


def sys_ioctl(s, cc):
    f = cc(s)

    fd = f.params[0]
    cmd = f.params[1]
    arg = f.params[2]

    print('{} {} sys_ioctl(fd={}, cmd={}, arg={})'.format(
        s.id, f.return_address(), fd, cmd, arg))

    return f.ret(value='sys_ioctl')


def sys_lseek(s, cc):
    f = cc(s)

    fd = f.params[0]
    offset = f.params[0]
    origin = f.params[0]

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

    print('{} {} sys_lseek(fd={}, offset={}, origin={}'.format(
        s.id, f.return_address(), fd, offset, origin))

    return f.ret(value=0)


def sys_mmap(s, cc):
    f = cc(s)

    addr = f.params[0]
    length = f.params[1]
    prot = f.params[2]
    flags = f.params[3]
    fd = f.params[4]
    offset = f.params[5]

    print('{} {} sys_mmap(addr={}, length={}, prot={}, flags={}, fd={}, offset={})'.format(
        s.id, f.return_address(), addr, length, prot, flags, fd, offset))

    if length.symbolic:
        print 'symbolic length not supported'
        return []

    ptr = bv.Constant(addr.size, s.memory.allocate(length))

    return f.ret(value=ptr)


def sys_mmap_pgoff(s, cc):
    f = cc(s)

    addr = f.params[0]
    length = f.params[1]
    prot = f.params[2]
    flags = f.params[3]
    fd = f.params[4]
    offset = f.params[5]

    print('{} {} sys_mmap_pgoff(file={}, addr={}, length={}, prot={}, flags={}, offset={})'.format(
        s.id, f.return_address(), addr, length, prot, flags, fd, offset))

    ptr = bv.Constant(addr.size, s.memory.allocate(length))

    return f.ret(value=ptr)


def sys_open(s, cc):
    f = cc(s)

    # TODO: can we control path

    path = f.params[0]
    flags = f.params[1]
    mode = f.params[2]

    o = DummyOutputBuffer()
    o.append_string(String(s, path))
    path = o.string[:-1]

    print('{} {} sys_open(path="{}", flags={}, mode={});'.format(
        s.id, f.return_address(), path, flags, mode))

    file_id = len(s.files) + 1

    s.files.append({
        'path':path,
        'mode':mode,
        'offset':0,
        'bytes':[]
    })

    print ('stream id: {}'.format(file_id))

    return f.ret(value=file_id)


def sys_ptrace(s, cc):
    f = cc(s)

    print('{} {} sys_ptrace()'.format(
        s.id, f.return_address()))

    return f.ret(value='sys_ptrace')


def sys_read(s, cc):
    function = cc(s)

    fd = function.params[0]
    buf = function.params[1]
    size = function.params[2]

    print('{} {} sys_read(fd={}, ptr={}, size={});'.format(
        s.id, function.return_address(), fd, buf, size))

    output = OutputBuffer(s, buf)

    if size.symbolic:
        raise NotImplementedError()
    else:
        if not fd.symbolic and fd.value == 0:
            for i in range(0, size.value):
                byte = bv.Symbol(8, unique_name('stdin_{0}'.format(i)))
                s.stdin.append(byte)
                output.append(byte)
        else:
            for i in range(0, size.value):
                byte = bv.Symbol(8, unique_name('sys_read_{0}'.format(i)))
                output.append(byte)

    return function.ret(value=size)


def sys_write(s, cc):
    function = cc(s)

    fd = function.params[0]
    buf = function.params[1]
    size = function.params[2]

    print('{} {} sys_write(fd={}, buf={}, size={})'.format(
        s.id, function.return_address(), fd, buf, size))

    o = DummyOutputBuffer()

    if size.symbolic:
        raise NotImplementedError()
    else:
        for i in range(0, size.value):
            o.append(s.read(buf + bv.Constant(buf.size, i), 8))

    output_string = o.string.strip('\r').strip('\n')
    print('{}: '.format(s.id) + colored(output_string, 'green'))

    return function.ret(value=bv.Constant(size.size, o.index))


def sys_unknown(s, cc):
    function = cc(s)

    print '{} {} sys_unknown({})'.format(
        s.id, function.return_address(), s.registers['eax'])

    return []


class LinuxX86(object):

    syscall_table = {
        0x01:sys_exit,
        0x03:sys_read,
        0x04:sys_write,
        0x36:sys_ioctl,
        0xc0:sys_mmap,
        0xc5:sys_fstat64,
        0xf0:sys_futex,
        0xfc:sys_exit_group,
    }

    def dispatch(self, s, i):
        if i.input0.value == 0:
            cc = LinuxX86Int0x80
        elif i.input0.value == 1:
            cc = LinuxX86Sysenter

        eax = s.registers['eax']
        if eax.symbolic:
            raise 'symbolic syscall'
        else:
            if eax.value in self.syscall_table:
                return self.syscall_table[eax.value](s, cc=cc)
            else:
                return sys_unknown(s, cc=cc)


class LinuxX86Int0x80(object):

    class Parameters(object):

        def __init__(self, state):
            self.state = state

        def __getitem__(self, index):
            if index == 0:
                return self.state.registers['ebx']
            elif index == 1:
                return self.state.registers['ecx']
            if index == 2:
                return self.state.registers['edx']
            if index == 3:
                return self.state.registers['esi']
            if index == 4:
                return self.state.registers['edi']
            if index == 5:
                return self.state.registers['ebp']

            raise ValueError(index)

    def __init__(self, state):
        self.state = state
        self.params = self.Parameters(state)

    def return_address(self):
        esp = self.state.registers['esp']
        return self.state.read(esp, 32)

    def ret(self, value=None):
        # load return address, adjust stack pointer
        esp = self.state.registers['esp']
        print self.state.memory.dump(range(esp.value, esp.value + 128))
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

class LinuxX86Sysenter(object):

    class Parameters(object):

        def __init__(self, state):
            self.state = state

        def __getitem__(self, index):
            if index == 0:
                return self.state.registers['ebx']
            elif index == 1:
                return self.state.registers['ecx']
            if index == 2:
                return self.state.registers['edx']
            if index == 3:
                return self.state.registers['esi']
            if index == 4:
                return self.state.registers['edi']
            if index == 5:
                return self.state.registers['ebp']

            raise ValueError(index)

    def __init__(self, state):
        self.state = state
        self.params = self.Parameters(state)

    def return_address(self):
        esp = self.state.registers['esp']
        return self.state.read(esp + bv.Constant(32, 12), 32)

    def ret(self, value=None):
        # load return address, adjust stack pointer
        esp = self.state.registers['esp']
        self.state.registers['ebp'] = self.state.read(esp, 32)
        self.state.registers['edx'] = self.state.read(esp + bv.Constant(32, 4), 32)
        self.state.registers['ecx'] = self.state.read(esp + bv.Constant(32, 8), 32)
        return_address = self.state.read(esp + bv.Constant(32, 12), 32)
        self.state.registers['esp'] = esp + bv.Constant(32, 16)

        # set return value (if set)
        if value is not None:
            if isinstance(value, int):
                self.state.registers['eax'] = bv.Constant(32, value)
            elif isinstance(value, str):
                self.state.registers['eax'] = bv.Symbol(32, unique_name(value))
            else:
                self.state.registers['eax'] = value

        return self.state.branch(return_address)


class LinuxX64(object):

    syscall_table = {
        0x01:  sys_exit,
        0x02:  sys_open,
        0x05:  sys_fstat,
        0x08:  sys_lseek,
        0x09:  sys_mmap,
        12: sys_brk,
        16: sys_ioctl,
        101:sys_ptrace,
        202:sys_futex,
        231:sys_exit_group,
    }

    def dispatch(self, s, i):
        rax = s.registers['rax']
        if rax.symbolic:
            raise 'symbolic syscall'
        else:
            if rax.value in self.syscall_table:
                return self.syscall_table[rax.value](s, cc=LinuxX64Syscall)
            else:
                return sys_unknown(s, cc=LinuxX64Syscall)


class LinuxX64Syscall(object):

    class Parameters(object):

        def __init__(self, state):
            self.state = state

        def __getitem__(self, index):
            if index == 0:
                return self.state.registers['rdi']
            elif index == 1:
                return self.state.registers['rsi']
            if index == 2:
                return self.state.registers['rdx']
            if index == 3:
                return self.state.registers['r10']
            if index == 4:
                return self.state.registers['r8']
            if index == 5:
                return self.state.registers['r9']

            raise ValueError(index)

    def __init__(self, state):
        self.state = state
        self.params = self.Parameters(state)

    def return_address(self):
        return bv.Constant(64, self.state.ip)

    def ret(self, value=None):
        return_address = bv.Constant(64, self.state.ip)

        # set return value (if set)
        if value is not None:
            if isinstance(value, int):
                self.state.registers['rax'] = bv.Constant(64, value)
            elif isinstance(value, str):
                self.state.registers['rax'] = bv.Symbol(64, unique_name(value))
            else:
                self.state.registers['rax'] = value

        print 'returning to {}'.format(return_address)

        return self.state.branch(return_address)


