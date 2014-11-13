#! /usr/bin/python2

from concolica import emulator
from concolica import log
from concolica import memory
from concolica import state
from concolica.syscall_emulation import linux

from smt import bitvector as bv

import argparse
import cPickle as pickle
import logging

logger = logging.getLogger('concolica')
logger.setLevel(logging.INFO)

ch = logging.StreamHandler()
ch.setLevel(log.REIL_INSTRUCTION)
ch.setFormatter(log.Formatter('%(message)s'))
logger.addHandler(ch)


def x86_validate(s, t):
    if s.ip != t['eip']:
        print 'eip {:08x} {:08x}'.format(s.ip, t['eip'])
        return False

    for reg in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']:
        if s.registers[reg].value != t[reg]:
            print '{} {:08x} {:08x}'.format(reg, s.registers[reg].value, t[reg])


    for reg in ['cf', 'pf', 'zf', 'sf', 'df', 'of']:

        # if we have explicitly undefined a flag, then this comparison would
        # fail...

        if reg in s.registers and s.registers[reg] is not None and s.registers[reg].value != t[reg]:
            print '{} {} {}'.format(reg, s.registers[reg].value, t[reg])
            #return False

    #for reg in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']:
    #    if s.registers[reg].value != t[reg]:
    #        print '{} {:032x} {:032x}'.format(reg, s.registers[reg].value, t[reg])
    #        return False

    return True


def x86_64_validate(s, t):
    if s.ip != t['rip']:
        print 'rip {:016x} {:016x}'.format(s.ip, t['rip'])
        return False

    for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
        if s.registers[reg].value != t[reg]:
            print '{} {:016x} {:016x}'.format(reg, s.registers[reg].value, t[reg])
            return False

    for reg in ['cf', 'pf', 'zf', 'sf', 'df', 'of']:

        # if we have explicitly undefined a flag, then this comparison would
        # fail...

        if reg in s.registers and s.registers[reg] is not None and s.registers[reg].value != t[reg]:
            print '{} {} {}'.format(reg, s.registers[reg].value, t[reg])
            return False

    #for reg in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15']:
    #    if s.registers[reg].value != t[reg]:
    #        print '{} {:032x} {:032x}'.format(reg, s.registers[reg].value, t[reg])
    #        return False

    return True


def validate(s, t, x86_64=False):
    if x86_64:
        return x86_64_validate(s, t)
    else:
        return x86_validate(s, t)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', '-f', action='store', default=None)
    args = parser.parse_args()

    s = state.State()
    global_memory = memory.StaticMemory()

    with open(args.file, 'rb') as trace_file:
        trace_data = pickle.load(trace_file)

    for base, bytes in trace_data['memory']:
        global_memory.add_mapping(base, bytes)

    s.memory = memory.DynamicMemory(global_memory)
    s.symbols = dict(trace_data['symbols'])

    x86_64 = False
    if 'rip' in trace_data['registers']:
        print 'trace appears to be x86_64'

        print trace_data['registers']

        x86_64 = True
        s.kernel = linux.LinuxX64()

        s.ip = trace_data['registers']['rip']
        s.registers['rip'] = s.ip

        for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
            s.registers[reg] = bv.Constant(64, trace_data['registers'][reg])

        for reg in ['cf', 'pf', 'af', 'zf', 'sf', 'df', 'of']:
            s.registers[reg] = bv.Constant(8, trace_data['registers'][reg])

        for reg in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15']:
            s.registers[reg] = bv.Constant(128, 0)

        s.registers['fsbase'] = bv.Constant(64, trace_data['registers']['fsbase'])
        s.registers['gsbase'] = bv.Constant(64, trace_data['registers']['gsbase'])

    else:
        print 'trace appears to be x86'
        s.kernel = linux.LinuxX86()

        s.ip = trace_data['registers']['eip']

        for reg in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']:
            s.registers[reg] = bv.Constant(32, trace_data['registers'][reg])

        for reg in ['cf', 'pf', 'af', 'zf', 'sf', 'df', 'of']:
            s.registers[reg] = bv.Constant(8, trace_data['registers'][reg])

        for reg in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']:
            s.registers[reg] = bv.Constant(128, 0)

        s.registers['gsbase'] = bv.Constant(32, trace_data['registers']['gsbase'])

    states = [s]

    i = 0
    while i < len(trace_data['trace']):
        s = states.pop()

        # this is a silly hack
        ip = s.ip
        ni = emulator.fetch_instruction(s, x86_64)
        s.ip = ip

        states += emulator.single_step(s, x86_64)

        if 'sysenter' in ni.mnemonic:
            ip_mask = trace_data['trace'][i]['eip'] & 0xfffff000
            while trace_data['trace'][i]['eip'] & 0xfffff000 == ip_mask:
                i += 1

        assert len(states) == 1
        if not validate(s, trace_data['trace'][i], x86_64):
            print 'VALIDATION FAILED SHIT SHIT SHIT SHIT'
            if s.ip not in [0x7f52036ca145, 0x7ffff7b3756d]:
                import sys
                sys.exit(0)

        print 'step {}'.format(i)
        i += 1