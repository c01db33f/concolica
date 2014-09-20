__author__ = 'c01db33f@gmail.com'

def update_syms(vdb, line):
    '''
    update the vdb currently loaded libraries
    '''

    trace = vdb.getTrace()
    trace._findLibraryMaps('\x7fELF')

def vdbExtension(vdb, trace):
    vdb.registerCmdExtension(update_syms)