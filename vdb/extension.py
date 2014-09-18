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
import shlex
import traceback

from concolica import debugger
from concolica import serialisation


def dump_state(vdb, line):
    '''
    continue execution concolically
    '''
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--arch', '-a', action='store', default='x86')
        parser.add_argument('--file', '-f', action='store', default='./dump.cc')
        args = shlex.split(line)
        args = parser.parse_args(args)

        trace = vdb.getTrace()

        p = debugger.VdbX86Process
        if args.arch == 'x86_64':
            p = debugger.VdbX86_64Process

        p = p(trace)

        s = p.state()

        serialisation.save(args.file, s)

    except:
        traceback.print_exc()


def vdbExtension(vdb, trace):
    vdb.registerCmdExtension(dump_state)
