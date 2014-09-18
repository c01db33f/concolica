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

    # unistd.h
    register_hook('sleep', sleep)
