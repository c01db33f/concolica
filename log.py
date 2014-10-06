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

import logging

from termcolor import colored


OUTPUT = 28
SYSCALL = 27
FUNCTION_CALL = 26
NATIVE_INSTRUCTION = 25
NATIVE_REGISTERS = 24
REIL_INSTRUCTION = 23
REIL_REGISTERS = 22


class Formatter(logging.Formatter):

    color_map = {
        OUTPUT:['white'],
        SYSCALL:['blue'],
        FUNCTION_CALL:['green'],
        NATIVE_INSTRUCTION:['yellow'],
        REIL_INSTRUCTION:['magenta']
    }


    def __init__(self, fmt, datefmt=None):
        logging.Formatter.__init__(self, fmt, datefmt)


    def format(self, record):
        message = logging.Formatter.format(self, record)

        if record.levelno in self.color_map:
            return colored(message, *self.color_map[record.levelno])
        else:
            return message


class StateLogger(logging.LoggerAdapter):

    def __init__(self, state):
        logging.LoggerAdapter.__init__(self, logging.getLogger('concolica'), {'state':state.id})
        self.state = state

    def output(self, msg):
        self.log(OUTPUT, msg)

    def syscall(self, f, msg, *args):
        self.log(SYSCALL,
                 '{} {} {}'.format(self.state.id, f.return_address(), msg.format(*args)))

    def function_call(self, f, msg, *args):
        if f is not None:
            self.log(FUNCTION_CALL,
                 '{} {} {}'.format(self.state.id, f.return_address(), msg.format(*args)))
        else:
            self.log(FUNCTION_CALL,
                 '{} {}'.format(self.state.id, msg.format(*args)))

    def native(self, hc, i):
        self.log(NATIVE_INSTRUCTION,
                 '{} {:4} {}'.format(self.state.id, hc, i))

    def reil(self, i):
        self.log(REIL_INSTRUCTION,
                 '{} {:4} {}'.format(self.state.id, self.state.il_index-1, i))