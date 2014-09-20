

import threading

import argparse
import functools
import os
import shlex
import struct
import subprocess
import time

from termcolor import colored

from concolica import emulator
from concolica import state
from concolica import interlocked
from concolica.vulnerabilities import *


max_threads = 24
active_threads = threading.BoundedSemaphore(max_threads)
available_states = threading.Semaphore(0)
exit_event = threading.Event()


def run_single_threaded(initial_states, x86_64):

    states = list(initial_states)

    while len(states) > 0:
        try:
            s = states.pop()
            ns = emulator.single_step(s, x86_64)
            for n in ns:
                states.append(n)
        except StateException, v:
            print v


def run_threaded(initial_states, x86_64):
    global active_threads
    global available_states

    states = interlocked.List(initial_states)

    for s in initial_states:
        available_states.release()

    def run(states):
        while not exit_event.is_set():
            active_threads.acquire()

            while available_states.acquire(blocking=False):
                try:
                    s = states.pop()
                    ns = emulator.single_step(s, x86_64)
                    for n in ns:
                        states.append(n)
                        available_states.release()
                except StateException, v:
                    print v

            active_threads.release()
            time.sleep(1.0)


    workers = []
    for i in range(0, max_threads):
        t = threading.Thread(target=run, args=(states,))
        t.start()
        workers.append(t)

    all_idle_count = 0
    try:
        while not exit_event.is_set():
            time.sleep(1)
            idle_count = active_threads._Semaphore__value
            print 'idle threads: {}'.format(idle_count)
            if idle_count == max_threads:
                all_idle_count += 1
                if all_idle_count == 3:
                    exit_event.set()
            else:
                all_idle_count = 0
    except KeyboardInterrupt:
        exit_event.set()

    for t in workers:
        t.join()
