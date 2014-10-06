#! /usr/bin/python2

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

import argparse
import logging

from concolica import log
from concolica import serialisation
from concolica import threaded

from concolica.library_emulation import calling_conventions
from concolica.library_emulation import libc
from concolica.library_emulation import unix
from concolica.syscall_emulation import linux


logger = logging.getLogger('concolica')
logger.setLevel(logging.INFO)

fh = logging.FileHandler('run_trace.log')
fh.setLevel(log.REIL_REGISTERS)
logger.addHandler(fh)

ch = logging.StreamHandler()
ch.setLevel(log.NATIVE_INSTRUCTION)
ch.setFormatter(log.Formatter('%(message)s'))
logger.addHandler(ch)


class CoverageScoringFunction(object):

    max_score = 0x100000000000000000

    def __init__(self):
        self.hit_count = dict()

    def __call__(self, state):
        ip = state.ip

        if ip not in self.hit_count:
            self.hit_count[ip] = 1
        else:
            self.hit_count[ip] += 1

        score = (self.max_score - (self.hit_count[ip] * 0x1000000000000000))
        score = score | ip
        return score


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', '-a', action='store', default='x86')
    parser.add_argument('--file', '-f', action='store', default='./dump.cc')
    args = parser.parse_args()

    state = serialisation.load(args.file)

    x86_64 = False
    if 'rax' in state.registers:
        x86_64 = True

    if not x86_64:
        state.kernel = linux.LinuxX86()
        libc.register_hooks(state, calling_conventions.Cdecl)
        unix.register_hooks(state, calling_conventions.Cdecl)
    else:
        state.kernel = linux.LinuxX64()
        libc.register_hooks(state, calling_conventions.Amd64SysV)
        unix.register_hooks(state, calling_conventions.Amd64SysV)

    # TODO: temporary fix until I dump a new state from debugger...
    state.log = log.StateLogger(state)

    #import pdb
    #pdb.set_trace()

    print 'about to run'

    for v in threaded.run_single_threaded([state], x86_64, CoverageScoringFunction()):
        print v

