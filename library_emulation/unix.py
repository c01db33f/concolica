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

# fcntl.h


def open(s, cc):
    f = cc(s)

    # TODO: can we control path

    path = f.params[0]
    flags = f.params[1]
    mode = f.params[2]

    o = DummyOutputBuffer()
    o.append_string(String(s, path))
    path = o.string[:-1]

    s.log.function_call(f, 'open(path="{}", flags={}, mode={})', path, flags, mode)

    file_id = len(s.files) + 1

    s.files.append({
        'path':path,
        'mode':mode,
        'offset':0,
        'bytes':dict()
    })

    print ('stream id: {}'.format(file_id))

    return f.ret(value=file_id)


# unistd.h

def read(s, cc):
    f = cc(s)

    fd = f.params[0]
    buf = f.params[1]
    size = f.params[2]

    s.log.function_call(f, 'read(fd={}, ptr={}, size={})', fd, buf, size)

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


def sleep(s, cc):
    f = cc(s)

    seconds = f.params[0]

    s.log.function_call(f, 'sleep(seconds={})', seconds)

    return f.ret(value=0)


def register_hooks(s, cc):
    h = s.function_hooks

    def register_hook(name, hook):
        h[name] = functools.partial(hook, cc=cc)

    # fcntl.h
    register_hook('open', open)

    # unistd.h
    register_hook('read', read)
    register_hook('sleep', sleep)
