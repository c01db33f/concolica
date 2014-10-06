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

    s.log.syscall(f, 'sys_brk({})', brk)

    if brk.value == 0:
        ptr = s.memory.allocate(0x10000)

    return f.ret(value=ptr)


def sys_chdir(s, cc):
    f = cc(s)

    filename = f.params[0]

    o = DummyOutputBuffer()
    o.append_string(String(s, filename))
    filename = o.string

    s.log.syscall(f, 'sys_chdir({})', filename)

    return f.ret(value='sys_chdir')


def sys_close(s, cc):
    f = cc(s)

    fd = f.params[0]

    s.log.syscall(f, 'sys_close({})', fd)

    if fd.symbolic:
        raise NotImplementedError()
    else:
        s.files.pop(fd.value - 1)

    return f.ret(value='sys_close')


def sys_exit(s, cc):
    f = cc(s)

    arg0 = f.params[0]

    s.log.syscall(f, 'sys_exit({})', arg0)

    return []


def sys_exit_group(s, cc):
    f = cc(s)

    arg0 = f.params[0]

    s.log.syscall(f, 'sys_exit_group({})', arg0)

    return []


def sys_fcntl(s, cc):
    f = cc(s)

    fd = f.params[0]
    cmd = f.params[1]

    if cmd.value == 0:
        cmd = 'F_DUPFD'
    elif cmd.value == 1:
        cmd = 'F_GETFD'
    elif cmd.value == 2:
        cmd = 'F_SETFD'
    elif cmd.value == 3:
        cmd = 'F_GETFL'
    elif cmd.value == 4:
        cmd = 'F_SETFL'
    elif cmd.value == 5:
        cmd = 'F_GETLK'
    elif cmd.value == 6:
        cmd = 'F_SETLK'
    elif cmd.value == 7:
        cmd = 'F_SETLKW'
    elif cmd.value == 8:
        cmd = 'F_SETOWN'
    elif cmd.value == 9:
        cmd = 'F_GETOWN'
    elif cmd.value == 10:
        cmd = 'F_SETSIG'
    elif cmd.value == 11:
        cmd = 'F_GETSIG'
    elif cmd.value == 12:
        cmd = 'F_GETLK64'
    elif cmd.value == 13:
        cmd = 'F_SETLK64'
    elif cmd.value == 14:
        cmd = 'F_SETLKW64'
    elif cmd.value == 15:
        cmd = 'F_SETOWN_EX'
    elif cmd.value == 16:
        cmd = 'F_GETOWN_EX'
    elif cmd.value == 17:
        cmd = 'F_GETOWNER_UIDS'

    s.log.syscall(f, 'sys_fcntl(fd={}, cmd={}, ...)', fd, cmd)

    return f.ret(value='sys_fcntl')


def sys_fstat(s, cc):
    f = cc(s)

    fd = f.params[0]
    statbuf = f.params[1]

    s.log.syscall(f, 'sys_fstat(fd={}, statbuf={})', fd, statbuf)

    o = OutputBuffer(s, statbuf)
    for i in range(0, 64): # sizeof(struct stat) == 64
        o.append(bv.Symbol(8, unique_name('fstat')))

    return f.ret(value=0)


def sys_fstat64(s, cc):
    f = cc(s)

    fd = f.params[0]
    statbuf = f.params[1]

    s.log.syscall(f, 'sys_fstat64(fd={}, statbuf={})', fd, statbuf)

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

    s.log.syscall(f, 'sys_futex(uaddr={}, op={}, val={}, utime={}, uaddr2={})', uaddr, op, val, utime, uaddr2)

    return f.ret(value='sys_futex')


def sys_ioctl(s, cc):
    f = cc(s)

    fd = f.params[0]
    cmd = f.params[1]
    arg = f.params[2]

    s.log.syscall(f, 'sys_ioctl(fd={}, cmd={}, arg={})', fd, cmd, arg)

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

    s.log.syscall(f, 'sys_lseek(fd={}, offset={}, origin={}', fd, offset, origin)

    return f.ret(value=0)


def sys_mmap(s, cc):
    f = cc(s)

    addr = f.params[0]
    length = f.params[1]
    prot = f.params[2]
    flags = f.params[3]
    fd = f.params[4]
    offset = f.params[5]

    s.log.syscall(f, 'sys_mmap(addr={}, length={}, prot={}, flags={}, fd={}, offset={})',
                  addr, length, prot, flags, fd, offset)

    if length.symbolic:
        raise NotImplementedError()

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

    s.log.syscall(f, 'sys_mmap_pgoff(file={}, addr={}, length={}, prot={}, flags={}, offset={})',
                  addr, length, prot, flags, fd, offset)

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

    s.log.syscall(f, 'sys_open(path="{}", flags={}, mode={})', path, flags, mode)

    file_id = len(s.files) + 1

    s.files.append({
        'path':path,
        'mode':mode,
        'offset':0,
        'bytes':dict()
    })

    print ('stream id: {}'.format(file_id))

    return f.ret(value=file_id)


def sys_ptrace(s, cc):
    f = cc(s)

    s.log.syscall(f, 'sys_ptrace()')

    return f.ret(value='sys_ptrace')


def sys_read(s, cc):
    f = cc(s)

    fd = f.params[0]
    buf = f.params[1]
    size = f.params[2]

    s.log.syscall(f, 'sys_read(fd={}, ptr={}, size={})', fd, buf, size)

    output = OutputBuffer(s, buf)

    if fd.symbolic:
        raise ValueError('wtf')

    if fd.value > len(s.files):
        return f.ret(value=0)
    else:
        file = s.files[fd.value]
        offset = file['offset']
        output = OutputBuffer(s, buf)

        real_fd = None
        if file['path'] not in ['stdin', 'stdout', 'stderr']:
            real_fd = open(file['path'], 'rb')

        if size.symbolic:
            raise NotImplementedError()
        elif real_fd is None:
            for i in xrange(0, size.value):
                b = bv.Symbol(8, 'file_{}_{:x}'.format(fd.value, offset))
                output.append(b)
                file['bytes'][offset] = b
                offset += 1
        else:
            real_fd.seek(offset, 0)
            for i in range(0, size.value):
                byte = real_fd.read(1)
                if len(byte) == 1:
                    if byte == '#':
                        b = bv.Symbol(8, 'file_{}_{:x}'.format(fd.value, offset))
                    else:
                        b = bv.Constant(8, ord(byte))
                    output.append(b)
                    file['bytes'][offset] = b
                    offset += 1
                else:
                    break

        file['offset'] = offset

        if real_fd is not None:
            real_fd.close()

    return f.ret(value=size)


def sys_setgroups(s, cc):
    f = cc(s)

    size = f.params[0]
    list = f.params[1]

    s.log.syscall(f, 'sys_setgroups(size={}, list={})', size, list)

    return f.ret(value=0)


def sys_setresgid(s, cc):
    f = cc(s)

    rgid = f.params[0]
    egid = f.params[1]
    sgid = f.params[2]

    s.log.syscall(f, 'sys_setresgid(rgid={}, egid={}, sgid={})', rgid, egid, sgid)

    return f.ret(value=0)


def sys_setresuid(s, cc):
    f = cc(s)

    ruid = f.params[0]
    euid = f.params[1]
    suid = f.params[2]

    s.log.syscall(f, 'sys_setresuid(ruid={}, euid={}, suid={})', ruid, euid, suid)

    return f.ret(value=0)


def sys_write(s, cc):
    f = cc(s)

    fd = f.params[0]
    buf = f.params[1]
    size = f.params[2]

    s.log.syscall(f, 'sys_write(fd={}, buf={}, size={})', fd, buf, size)

    o = DummyOutputBuffer()

    if size.symbolic:
        raise NotImplementedError()
    else:
        for i in range(0, size.value):
            o.append(s.read(buf + bv.Constant(buf.size, i), 8))

    output_string = o.string.strip('\r').strip('\n')
    s.log.output(output_string)

    return f.ret(value=bv.Constant(size.size, o.index))


def sys_unknown(s, number, cc):
    f = cc(s)

    s.log.syscall(f, 'sys_unknown({})', number)

    return []


class LinuxX86(object):

    syscall_table = {
        0x01:sys_exit,
        0x03:sys_read,
        0x04:sys_write,
        0x36:sys_ioctl,
        0xc0:sys_mmap,
        0xc5:sys_fstat64,
        0xce:sys_setgroups,
        0xd0:sys_setresuid,
        0xd2:sys_setresgid,
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
                return sys_unknown(s, eax.value, cc=cc)


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
        0x03:  sys_close,
        0x05:  sys_fstat,
        0x08:  sys_lseek,
        0x09:  sys_mmap,
        0x48:  sys_fcntl,
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
                return sys_unknown(s, rax.value, cc=LinuxX64Syscall)


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


