import argparse
import os
import pickle
import shlex
import struct
import traceback


def x86_get_gsbase(trace):
    sp = trace.getStackCounter()
    pc = trace.getProgramCounter()

    regsave = trace.getRegisters()
    spsave = trace.readMemory(sp, 16)
    pcsave = trace.readMemory(pc, 16)

    trace.writeMemory(pc, '\x65\xa1\x00\x00\x00\x00')
    trace._syncRegs()

    try:
        tid = trace.getMeta('ThreadId', 0)
        trace.platformStepi()
        os.waitpid(tid, 0)
        eax = trace.getRegisterByName('eax')

        return eax
    finally:
        trace.writeMemory(sp, spsave)
        trace.writeMemory(pc, pcsave)
        trace.setRegisters(regsave)


def x86_64_get_fsbase(trace):
    sp = trace.getStackCounter()
    pc = trace.getProgramCounter()

    regsave = trace.getRegisters()
    spsave = trace.readMemory(sp, 8)
    pcsave = trace.readMemory(pc, 2)

    __arch_prctl = 0x9e

    trace.writeMemory(pc, '\x0f\x05')
    trace.setRegisterByName('rax', __arch_prctl)
    trace.setRegisterByName('rdi', 0x1003)
    trace.setRegisterByName('rsi', sp)
    trace._syncRegs()

    try:
        tid = trace.getMeta('ThreadId', 0)
        trace.platformStepi()
        os.waitpid(tid, 0)
        rax = trace.getRegisterByName('rax')
        if rax & 0x8000000000000000:
            print 'arch_prctl failed! {:x}'.format(rax)
        else:
            return struct.unpack('<Q', trace.readMemory(sp, 8))[0]
    finally:
        trace.writeMemory(sp, spsave)
        trace.writeMemory(pc, pcsave)
        trace.setRegisters(regsave)


def x86_64_get_gsbase(trace):
    sp = trace.getStackCounter()
    pc = trace.getProgramCounter()

    regsave = trace.getRegisters()
    spsave = trace.readMemory(sp, 8)
    pcsave = trace.readMemory(pc, 2)

    __arch_prctl = 0x9e

    trace.writeMemory(pc, '\x0f\x05')
    trace.setRegisterByName('rax', __arch_prctl)
    trace.setRegisterByName('rdi', 0x1004)
    trace.setRegisterByName('rsi', sp)
    trace._syncRegs()

    try:
        tid = trace.getMeta('ThreadId', 0)
        trace.platformStepi()
        os.waitpid(tid, 0)
        rax = trace.getRegisterByName('rax')
        if rax & 0x8000000000000000:
            print 'arch_prctl failed! {:x}'.format(rax)
        else:
            return struct.unpack('<Q', trace.readMemory(sp, 8))[0]
    finally:
        trace.writeMemory(sp, spsave)
        trace.writeMemory(pc, pcsave)
        trace.setRegisters(regsave)


def trace_memory(trace):
    memory = []
    maps = trace.getMemoryMaps()

    for base, size, perm, name in maps:
        try:
            bytes = trace.readMemory(base, size)
            memory.append((base, bytes))
        except:
            pass

    return memory


def x86_trace_registers(trace):
    registers = dict()

    context = trace.getRegisterContext(trace.getCurrentThread())
    registers['eip'] = context.getProgramCounter()

    for reg in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp']:
        registers[reg] = context.getRegisterByName(reg)

    for reg in ['cf', 'pf', 'af', 'zf', 'sf', 'df', 'of']:
        registers[reg] = context.getRegisterByName(reg.upper())

    #for reg in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7']:
    #    registers[reg] = context.getRegisterByName(reg)

    registers['gsbase'] = x86_get_gsbase(trace)

    return registers


def x86_64_trace_registers(trace):
    registers = dict()

    context = trace.getRegisterContext(trace.getCurrentThread())
    registers['rip'] = context.getProgramCounter()

    for reg in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
        registers[reg] = context.getRegisterByName(reg)

    for reg in ['cf', 'pf', 'af', 'zf', 'sf', 'df', 'of']:
        registers[reg] = context.getRegisterByName(reg.upper())

    #for reg in ['xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15']:
    #    registers[reg] = context.getRegisterByName('x' + reg[1:]) & 0xffffffffffffffffffffffffffffffff

    registers['fsbase'] = x86_64_get_fsbase(trace)
    registers['gsbase'] = x86_64_get_gsbase(trace)

    return registers


def trace_registers(trace, x86_64=False):
    if x86_64:
        return x86_64_trace_registers(trace)
    else:
        return x86_trace_registers(trace)


def trace_symbols(trace):
    symbols = dict()

    trace._findLibraryMaps('\x7fELF')

    for lib_name in trace.getNormalizedLibNames():
        if lib_name == '[vdso]':
            continue
        for sym in trace.getSymsForFile(lib_name):
            if len(sym.name) == 0:
                continue
            if sym.value not in symbols or len(sym.name) < len(symbols[sym.value]):
                symbols[sym.value] = sym.name

    return symbols


def save_state(vdb, line):
    '''
    save current execution state to make a testcase for deus_ex_concolica
    '''

    parser = argparse.ArgumentParser()
    parser.add_argument('--file', '-f', action='store', default=None)
    parser.add_argument('--arch', '-a', action='store', default='x86')
    args = shlex.split(line)
    args = parser.parse_args(args)

    trace_data = dict()

    x86_64 = False
    if args.arch == 'x86_64':
        x86_64 = True

    try:
        trace = vdb.getTrace()

        trace_data['memory'] = trace_memory(trace)
        trace_data['registers'] = trace_registers(trace, x86_64)
        trace_data['symbols'] = trace_symbols(trace)

    except:
        traceback.print_exc()

    finally:
        with open(args.file, 'wb') as trace_file:
            pickle.dump(trace_data, trace_file, pickle.HIGHEST_PROTOCOL)


def save_trace(vdb, line):
    '''
    trace execution to make a testcase for deus_ex_concolica
    '''

    parser = argparse.ArgumentParser()
    parser.add_argument('--file', '-f', action='store', default=None)
    parser.add_argument('--arch', '-a', action='store', default='x86')
    args = shlex.split(line)
    args = parser.parse_args(args)

    trace_data = dict()

    x86_64 = False
    if args.arch == 'x86_64':
        x86_64 = True

    trace_datas = []

    try:
        trace = vdb.getTrace()

        trace_data['memory'] = trace_memory(trace)
        trace_data['registers'] = trace_registers(trace, x86_64)
        trace_data['symbols'] = trace_symbols(trace)
        trace_data['trace'] = []

        i = 0
        while True:
            print '{} steps'.format(i)
            i += 1
            trace.stepi()

            trace_data['trace'].append(trace_registers(trace, x86_64))
    except:
        traceback.print_exc()

    finally:
        with open(args.file, 'wb') as trace_file:
            pickle.dump(trace_datas, trace_file, pickle.HIGHEST_PROTOCOL)


def vdbExtension(vdb, trace):
    vdb.registerCmdExtension(save_trace)
