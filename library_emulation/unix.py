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

def fcntl(s, cc):
    f = cc(s)

    return f.ret()


def open(s, cc):
    f = cc(s)

    # TODO: can we control path

    path = f.params[0]
    flags = f.params[1]
    mode = f.params[2]

    o = DummyOutputBuffer()
    o.append_string(String(s, path))
    path = o.string[:-1]

    print('{} {} open(path="{}", flags={}, mode={});'.format(
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


# unistd.h

def sleep(s, cc):
    f = cc(s)

    seconds = f.params[0]

    print('{} {} sleep(seconds={});'.format(
        s.id, f.return_address(), seconds))

    return f.ret(value=0)


def register_hooks(s, cc):
    h = s.function_hooks

    def register_hook(name, hook):
        h[name] = functools.partial(hook, cc=cc)

    # fcntl.h
    register_hook('open', open)

    # unistd.h
    register_hook('sleep', sleep)
