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

########################################################################
# GENERAL EXCEPTIONS                                                   #
########################################################################


class StateException(BaseException):

    def __init__(self, state):
        self.state = state

    def __str__(self):
        return '{} {:x} exception'.format(
            self.state.id, self.state.ip)


class EmulationFinished(StateException):
    pass


class InstructionNotTranslated(StateException):
    pass


class SyscallNotSupported(StateException):
    pass


class TargetReached(StateException):
    pass


########################################################################
# VULNERABILITIES                                                      #
########################################################################

########################################################################
# MEMORY ACCESS ISSUES                                                 #
########################################################################


class InvalidMemoryAccess(StateException):

    def __init__(self, state, address):
        StateException.__init__(self, state)
        self.address = address

    def __str__(self):
        return '{} {:x} invalid memory access: {}'.format(
            self.state.id, self.state.ip, self.address)


# reads

class InvalidRead(InvalidMemoryAccess):

    def __init__(self, state, address):
        InvalidMemoryAccess.__init__(self, state, address)

    def __str__(self):
        return '{} {:x} invalid read: {:x}'.format(
            self.state.id, self.state.ip, self.address)


class UninitialisedRead(InvalidRead):
    
    def __init__(self, state, address):
        InvalidRead.__init__(self, state, address)

    def __str__(self):
        return '{} {:x} uninitialised read: {:x}'.format(
            self.state.id, self.state.ip, self.address)


class UnmappedRead(InvalidRead):
    
    def __init__(self, state, address):
        InvalidRead.__init__(self, state, address)

    def __str__(self):
        return '{} {:x} unmapped read: {:x}'.format(
            self.state.id, self.state.ip, self.address)


class UseAfterFree(InvalidRead):

    def __init__(self, state, address):
        InvalidRead.__init__(self, state, address)

    def __str__(self):
        return '{} {:x} use-after-free: {:x}'.format(
            self.state.id, self.state.ip, self.address)


class ArbitraryRead(InvalidRead):
    
    def __init__(self, state, address):
        InvalidRead.__init__(self, state, address)

    def __str__(self):
        return '{} {:x} arbitrary read: {}'.format(
            self.state.id, self.state.ip, self.address)


# writes

class InvalidWrite(InvalidMemoryAccess):
    
    def __init__(self, state, address, value):
        InvalidMemoryAccess.__init__(self, state, address)
        self.value = value

    def __str__(self):
        return '{} {:x} invalid write: {:x} {}'.format(
            self.state.id, self.state.ip, self.address, self.value)


class UnmappedWrite(InvalidWrite):
    
    def __init__(self, state, address, value):
        InvalidWrite.__init__(self, state, address, value)

    def __str__(self):
        return '{} {:x} unmapped write: {} {}'.format(
            self.state.id, self.state.ip, self.address, self.value)


class ArbitraryWrite(InvalidWrite):
    
    def __init__(self, state, address, value):
        InvalidWrite.__init__(self, state, address, value)

    def __str__(self):
        return '{} {:x} arbitrary write: {} {}'.format(
            self.state.id, self.state.ip, self.address, self.value)


# execute

class InvalidExecution(InvalidMemoryAccess):
    
    def __init__(self, state, address):
        InvalidMemoryAccess.__init__(self, state, address)

    def __str__(self):
        return '{} {:x} invalid execution: {}'.format(
            self.state.id, self.state.ip, self.address)
            

class ArbitraryExecution(InvalidExecution):
    
    def __init__(self, state, address):
        InvalidExecution.__init__(self, state, address)

    def __str__(self):
        return '{} {:x} arbitrary execution: {}'.format(
            self.state.id, self.state.ip, self.address)


class SymbolicExecution(InvalidExecution):

    def __init__(self, state, address, byte):
        InvalidExecution.__init__(self, state, address)
        self.byte = byte

    def __str__(self):
        return '{} {:x} symbolic execution: {}'.format(
            self.state.id, self.state.ip, self.byte.smt2())