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

from concolica import serialisation
from concolica import threaded

from concolica.library_emulation import calling_conventions
from concolica.library_emulation import libc
from concolica.library_emulation import unix
from concolica.syscall_emulation import linux


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', '-a', action='store', default='x86')
    parser.add_argument('--file', '-f', action='store', default='./dump.cc')
    args = parser.parse_args()

    state = serialisation.load(args.file)

    x86_64 = False
    if args.arch == 'x86':
        state.kernel = linux.LinuxX86()
        libc.register_hooks(state, calling_conventions.Cdecl)
        unix.register_hooks(state, calling_conventions.Cdecl)
    else:
        x86_64 = True
        state.kernel = linux.LinuxX64()
        libc.register_hooks(state, calling_conventions.Amd64SysV)
        unix.register_hooks(state, calling_conventions.Amd64SysV)

    #import pdb
    #pdb.set_trace()

    threaded.run_threaded([state], x86_64)

